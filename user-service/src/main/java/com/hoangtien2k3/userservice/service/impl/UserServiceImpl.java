package com.hoangtien2k3.userservice.service.impl;

import com.google.gson.Gson;
import com.hoangtien2k3.userservice.constant.KafkaConstant;
import com.hoangtien2k3.userservice.event.EventProducer;
import com.hoangtien2k3.userservice.exception.wrapper.*;
import com.hoangtien2k3.userservice.model.dto.request.*;
import com.hoangtien2k3.userservice.model.dto.response.InformationMessage;
import com.hoangtien2k3.userservice.model.dto.response.JwtResponseMessage;
import com.hoangtien2k3.userservice.model.entity.RoleName;
import com.hoangtien2k3.userservice.model.entity.User;
import com.hoangtien2k3.userservice.repository.UserRepository;
import com.hoangtien2k3.userservice.security.jwt.JwtProvider;
import com.hoangtien2k3.userservice.security.userprinciple.UserDetailService;
import com.hoangtien2k3.userservice.security.userprinciple.UserPrinciple;
import com.hoangtien2k3.userservice.service.RoleService;
import com.hoangtien2k3.userservice.service.UserService;

import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import jakarta.transaction.Transactional;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;
    private final UserDetailService userDetailsService;
    private final ModelMapper modelMapper;
    private final RoleService roleService;

    Gson gson = new Gson();

    @Autowired
    EventProducer eventProducer;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Value("${refresh.token.url}")
    private String refreshTokenUrl;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           JwtProvider jwtProvider,
                           UserDetailService userDetailsService,
                           ModelMapper modelMapper,
                           RoleService roleService) {

        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.modelMapper = modelMapper;
        this.roleService = roleService;
    }

    @Override
    public Mono<User> register(SignUp signUp) {
        return Mono.fromCallable(() -> {

            if (existsByUsername(signUp.getUsername()))
                throw new EmailOrUsernameNotFoundException("Username exists: " + signUp.getUsername());

            if (existsByEmail(signUp.getEmail()))
                throw new EmailOrUsernameNotFoundException("Email exists: " + signUp.getEmail());

            if (existsByPhoneNumber(signUp.getPhone()))
                throw new PhoneNumberNotFoundException("Phone exists: " + signUp.getPhone());

            User user = modelMapper.map(signUp, User.class);
            user.setPassword(passwordEncoder.encode(signUp.getPassword()));

            user.setRoles(signUp.getRoles()
                    .stream()
                    .map(role -> roleService.findByName(mapToRoleName(role))
                            .orElseThrow(() -> new RuntimeException("Role not found")))
                    .collect(Collectors.toSet()));

            return userRepository.save(user);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    private RoleName mapToRoleName(String roleName) {
        return switch (roleName) {
            case "ADMIN", "admin", "Admin" -> RoleName.ADMIN;
            case "PM", "pm", "Pm" -> RoleName.PM;
            case "USER", "user", "User" -> RoleName.USER;
            default -> null;
        };
    }

    @Override
    public Mono<JwtResponseMessage> login(Login signInForm) {
        return Mono.fromCallable(() -> {

            String usernameOrEmail = signInForm.getUsername();
            boolean isEmail = usernameOrEmail.contains("@gmail.com");

            UserDetails userDetails = isEmail
                    ? userDetailsService.loadUserByEmail(usernameOrEmail)
                    : userDetailsService.loadUserByUsername(usernameOrEmail);

            if (!passwordEncoder.matches(signInForm.getPassword(), userDetails.getPassword()))
                throw new PasswordNotFoundException("Incorrect password");

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userDetails, signInForm.getPassword(), userDetails.getAuthorities());

            SecurityContextHolder.getContext().setAuthentication(authentication);

            String accessToken = jwtProvider.createToken(authentication);
            String refreshToken = jwtProvider.createRefreshToken(authentication);

            UserPrinciple user = (UserPrinciple) userDetails;

            return JwtResponseMessage.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken)
                    .information(InformationMessage.builder()
                            .id(user.id())
                            .fullname(user.fullname())
                            .username(user.username())
                            .email(user.email())
                            .phone(user.phone())
                            .gender(user.gender())
                            .avatar(user.avatar())
                            .roles(user.roles())
                            .build())
                    .build();
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Void> logout() {
        return Mono.fromRunnable(() -> {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            SecurityContextHolder.clearContext();
            if (auth != null && auth.isAuthenticated()) {
                String token = getCurrentToken();
                if (token != null) jwtProvider.reduceTokenExpiration(token);
            }
        }).subscribeOn(Schedulers.boundedElastic()).then();
    }

    private String getCurrentToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.getCredentials() instanceof String)
            return (String) auth.getCredentials();
        return null;
    }

    @Transactional
    @Override
    public Mono<User> update(Long id, SignUp updateDTO) {
        return Mono.fromCallable(() -> {
            User existingUser = userRepository.findById(id)
                    .orElseThrow(() -> new UserNotFoundException("User not found: " + id));

            modelMapper.map(updateDTO, existingUser);
            existingUser.setPassword(passwordEncoder.encode(updateDTO.getPassword()));

            return userRepository.save(existingUser);
        }).subscribeOn(Schedulers.boundedElastic());
    }

    @Transactional
    @Override
    public Mono<String> changePassword(ChangePasswordRequest request) {
        return Mono.fromCallable(() -> {

            UserDetails loggedIn = getCurrentUserDetails();
            String username = loggedIn.getUsername();

            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new UserNotFoundException("User not found " + username));

            if (!passwordEncoder.matches(request.getOldPassword(), loggedIn.getPassword()))
                throw new PasswordNotFoundException("Incorrect password");

            if (!Objects.equals(request.getNewPassword(), request.getConfirmPassword()))
                return "Password changed failed.";

            user.setPassword(passwordEncoder.encode(request.getNewPassword()));
            userRepository.save(user);

            EmailDetails emailDetails = emailDetailsConfig(username);

            eventProducer.send(KafkaConstant.PROFILE_ONBOARDING_TOPIC, gson.toJson(emailDetails))
                    .subscribeOn(Schedulers.boundedElastic())
                    .subscribe();

            return "Password changed successfully";

        }).subscribeOn(Schedulers.boundedElastic());
    }

    private EmailDetails emailDetailsConfig(String username) {
        return EmailDetails.builder()
                .recipient("hoangtien2k3dev@gmail.com")
                .msgBody(textSendEmailChangePasswordSuccessfully(username))
                .subject("Password Change Successful: " +
                        LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                .attachment("Please keep this information secure.")
                .build();
    }

    public String textSendEmailChangePasswordSuccessfully(String username) {
        return "Hey " + username + "!\n\n" +
                "Your password has been successfully changed.\n" +
                "If this wasn't you, please contact support immediately.\n\n" +
                "Best regards,\nSupport Team";
    }

    private UserDetails getCurrentUserDetails() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()
                && auth.getPrincipal() instanceof UserDetails)
            return (UserDetails) auth.getPrincipal();

        throw new UserNotAuthenticatedException("User not authenticated.");
    }

    @Transactional
    @Override
    public Mono<String> delete(Long id) {
        return Mono.fromRunnable(() -> userRepository.findById(id)
                .ifPresentOrElse(
                        user -> {
                            try {
                                userRepository.delete(user);
                            } catch (DataAccessException e) {
                                throw new RuntimeException("Error deleting user: " + id, e);
                            }
                        },
                        () -> {
                            throw new UserNotFoundException("User not found: " + id);
                        }))
                .subscribeOn(Schedulers.boundedElastic())
                .then(Mono.just("User with id " + id + " deleted successfully."));
    }

    public Mono<String> refreshToken(String refreshToken) {
        return webClientBuilder.build()
                .post()
                .uri(refreshTokenUrl)
                .header("Refresh-Token", refreshToken)
                .retrieve()
                .onStatus(HttpStatus::is4xxClientError,
                        response -> Mono.error(new IllegalArgumentException("Invalid refresh token")))
                .bodyToMono(JwtResponseMessage.class)
                .map(JwtResponseMessage::getAccessToken);
    }

    @Override
    public Mono<User> findById(Long userId) {
        return Mono.fromCallable(() ->
                        userRepository.findById(userId)
                                .orElseThrow(() -> new UserNotFoundException("User not found " + userId)))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<User> findByUsername(String username) {
        return Mono.fromCallable(() ->
                        userRepository.findByUsername(username)
                                .orElseThrow(() -> new UserNotFoundException("User not found " + username)))
                .subscribeOn(Schedulers.boundedElastic());
    }

    @Override
    public Mono<Page<UserDto>> findAllUsers(int page, int size, String sortBy, String sortOrder) {
        return Mono.fromCallable(() -> {
            Sort sort = Sort.by(Sort.Direction.fromString(sortOrder), sortBy);
            PageRequest pageRequest = PageRequest.of(page, size, sort);
            Page<User> users = userRepository.findAll(pageRequest);
            return users.map(user -> modelMapper.map(user, UserDto.class));
        }).subscribeOn(Schedulers.boundedElastic());
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }

    public boolean existsByPhoneNumber(String phone) {
        return userRepository.existsByPhoneNumber(phone);
    }
}

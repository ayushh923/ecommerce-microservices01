package com.hoangtien2k3.userservice.model.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * System roles available for application users.
 * This enum is stored as STRING in the database (see Role.java).
 */
@Getter
@RequiredArgsConstructor
public enum RoleName {
    USER,    // Regular user
    PM,      // Project / Product Manager
    ADMIN    // System administrator
}

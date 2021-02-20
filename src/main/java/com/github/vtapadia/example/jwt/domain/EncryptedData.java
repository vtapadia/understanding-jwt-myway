package com.github.vtapadia.example.jwt.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor @AllArgsConstructor
public class EncryptedData {
    private String encrypted;
}

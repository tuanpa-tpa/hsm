package com.example.hsm;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class KeypairController {
    private final KeypairService keypairService;

    @PostMapping("/create-keypair/{name}")
    public ResponseEntity<?> createKeypair(@PathVariable String name) {
        return ResponseEntity.ok(keypairService.createKey(name));
    }

    @PostMapping("/create-csr/{name}")
    public ResponseEntity<?> createCsr(@PathVariable String name) {
        return ResponseEntity.ok(keypairService.createCer(name));
    }
}

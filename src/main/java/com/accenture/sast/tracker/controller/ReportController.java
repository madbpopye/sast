package com.accenture.sast.tracker.controller;

import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/reports")
public class ReportController {

    private static final String REPORT_DIR = "C:/reports/";

    // ── VULNERABILITY V5: Path Traversal (CWE-22) ────────────────────────────
    // The filename parameter is used directly when building the File path.
    // An attacker can supply: ../../Windows/System32/drivers/etc/hosts
    // to read any file the process has access to, regardless of REPORT_DIR.
    // Fix: resolve the path, then verify it starts with REPORT_DIR:
    //   Path resolved = Paths.get(REPORT_DIR).resolve(filename).normalize();
    //   if (!resolved.startsWith(Paths.get(REPORT_DIR))) throw new ...;
    // ─────────────────────────────────────────────────────────────────────────
    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String filename) throws IOException {
        Path reportDir = Paths.get(REPORT_DIR).toAbsolutePath().normalize();
        Path resolved = reportDir.resolve(filename).normalize();

        if(!resolved.startsWith(reportDir)){
            return ResponseEntity.badRequest().build();
        }
        File file = resolved.toFile();

        if (!file.exists()) {
            return ResponseEntity.notFound().build();
        }

        byte[] content = Files.readAllBytes(file.toPath());
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(new ByteArrayResource(content));
    }
}

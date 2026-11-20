package com.accenture.sast.tracker.controller;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

// ── VULNERABILITY V8: Reflected Cross-Site Scripting (CWE-79) ────────────────
// The message parameter is embedded directly into the HTML response body without
// any output encoding. An attacker can inject a script payload:
//   GET /api/status?message=<script>alert(document.cookie)</script>
// and the browser executes it in the context of the application's origin,
// enabling session hijacking, credential theft, or malicious redirects.
// Fix: encode the parameter before embedding it, e.g.:
//   org.springframework.web.util.HtmlUtils.htmlEscape(message)
// and add a Content-Security-Policy response header to restrict script execution.
// ─────────────────────────────────────────────────────────────────────────────
@RestController
public class StatusController {

    @GetMapping(value = "/api/status", produces = MediaType.TEXT_HTML_VALUE)
    public String status(@RequestParam(defaultValue = "Welcome") String message) {
        String safeMessage = HtmlUtils.htmlEscape(message);
        return "<html><body><h1>" + safeMessage + "</h1>" +
               "<p>Employee Tracker is running.</p></body></html>";
    }
}

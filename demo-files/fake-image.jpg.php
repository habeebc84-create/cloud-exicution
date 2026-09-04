<?php
/*
 * ============================================================
 *  DEMO FILE — CloudGuard AI Capstone Presentation
 *  ⚠ THIS IS A HARMLESS SIMULATION FILE FOR CLASS DEMO ONLY
 *  ATTACK TYPE: Double Extension / Extension Spoofing
 * ============================================================
 *
 *  ATTACK EXPLANATION:
 *  This file is named "fake-image.jpg.php"
 *  A basic validator checking only the LAST extension sees ".php"
 *  A naive validator checking only "contains .jpg" might ALLOW it!
 *  The web server will execute it as PHP — not display as image.
 *
 *  This is the most common real-world file upload bypass!
 *
 *  HOW TO USE IN DEMO:
 *  1. HACKER MODE ON → upload this → VULNERABLE INJECTION logged
 *     Observe: original name "fake-image.jpg.php" preserved!
 *  2. SECURE MODE → upload this → REJECTED
 *     Reason: magic bytes don't match JPG [FF D8 FF] signature
 *
 *  KEY TEACHING POINT:
 *  "Never trust the filename extension — always read magic bytes!"
 * ============================================================
 */

echo "[DEMO] Double-Extension Attack Simulation";
echo "[DEMO] This file looks like a .jpg but executes as PHP!";
?>

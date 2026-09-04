<?php
/*
 * ============================================================
 *  DEMO FILE — CloudGuard AI Capstone Presentation
 *  ⚠ THIS IS A HARMLESS SIMULATION FILE FOR CLASS DEMO ONLY
 *  It contains NO real malicious code.
 * ============================================================
 *
 *  In a real attack, a hacker would upload a file like this
 *  to a vulnerable server. If the server has no validation,
 *  this .php file would execute on the server, giving the
 *  attacker full control (Remote Code Execution).
 *
 *  HOW TO USE IN DEMO:
 *  1. Enable "Hacker Mode" toggle in CloudGuard AI
 *  2. Upload this file — it will pass ALL filters
 *  3. Notice: VULNERABLE INJECTION badge appears in the log
 *  4. The original filename "shell.php" is preserved (DANGEROUS!)
 *
 *  Switch back to SECURE MODE and try again → REJECTED!
 * ============================================================
 */

// SIMULATED malicious payload (does nothing — for demo only)
echo "[DEMO] Web Shell Simulation — CloudGuard AI Capstone";
echo "[DEMO] In a real attack, this would expose system access.";

/*
 * A real web shell might look like:
 * system($_GET['cmd']);   ← executes any OS command via URL
 * eval($_POST['code']);   ← runs any PHP code sent by hacker
 *
 * CloudGuard Secure Mode blocks this because:
 * → .php has NO valid image/PDF magic bytes
 * → Magic byte check fails → file REJECTED
 */
?>

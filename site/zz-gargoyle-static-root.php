<?php
/**
 * Plugin Name: Gargoyle static root
 * Description: Serves /html/index.html for the site root so the static Gargoyle pages front the site. Everything else is WordPress as before. Remove this file to restore the WordPress front page.
 * Version: 1.0 (2026-10-20)
 */
if (PHP_SAPI === 'cli') { return; }
$gsr_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$gsr_path = isset($_SERVER['REQUEST_URI']) ? strtok($_SERVER['REQUEST_URI'], '?') : '/';
if (($gsr_method === 'GET' || $gsr_method === 'HEAD') && ($gsr_path === '/' || $gsr_path === '/index.php')) {
    $gsr_file = ABSPATH . 'index.html';
    if (is_file($gsr_file) && is_readable($gsr_file)) {
        $gsr_mtime = filemtime($gsr_file);
        header('Content-Type: text/html; charset=UTF-8');
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $gsr_mtime) . ' GMT');
        header('Cache-Control: public, max-age=600');
        header('X-Gargoyle-Static-Root: index.html');
        if ($gsr_method === 'GET') { readfile($gsr_file); }
        exit;
    }
}

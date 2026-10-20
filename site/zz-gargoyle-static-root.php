<?php
/**
 * Plugin Name: Gargoyle static pages
 * Description: Serves the static Gargoyle pages from /html through PHP: "/" -> index.html, "/report" -> report.html, "/elyon-sol" -> elyon-sol.html. Going through PHP keeps them inside the platform's page-cache ban, which static files are not. Everything else is WordPress as before. Remove this file to restore the WordPress front page.
 * Version: 1.1 (2026-10-20)
 */
if (PHP_SAPI === 'cli') { return; }
$gsr_method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$gsr_path = isset($_SERVER['REQUEST_URI']) ? strtok($_SERVER['REQUEST_URI'], '?') : '/';
$gsr_path = rtrim($gsr_path, '/');
$gsr_map = array(
    ''           => 'index.html',
    '/index.php' => 'index.html',
    '/report'    => 'report.html',
    '/elyon-sol' => 'elyon-sol.html',
);
if (($gsr_method === 'GET' || $gsr_method === 'HEAD') && isset($gsr_map[$gsr_path])) {
    $gsr_file = ABSPATH . $gsr_map[$gsr_path];
    if (is_file($gsr_file) && is_readable($gsr_file)) {
        $gsr_mtime = filemtime($gsr_file);
        header('Content-Type: text/html; charset=UTF-8');
        header('Last-Modified: ' . gmdate('D, d M Y H:i:s', $gsr_mtime) . ' GMT');
        header('Cache-Control: public, max-age=600');
        header('X-Gargoyle-Static-Root: ' . $gsr_map[$gsr_path]);
        if ($gsr_method === 'GET') { readfile($gsr_file); }
        exit;
    }
}

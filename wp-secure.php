<?php
/**
 * Plugin Name: WP Secure
 * Description: A security plugin with a firewall and scanner.
 * Version: 1.0
 * Author: Ali Raza
 */


if (!defined('ABSPATH')) exit;

class WPSecure {

    private $api_key = 'YY5TW8pLhEO4wgLCnCXaDxRPVwid5QEVX8Czqf4LfHE';

    public function __construct() {
        add_action('admin_menu', [$this, 'menu']);
        add_action('admin_enqueue_scripts', [$this, 'scripts']);

        add_action('wp_ajax_wpsecure_get_plugins', [$this, 'get_plugins']);
        add_action('wp_ajax_wpsecure_scan_plugin', [$this, 'scan_plugin']);
        add_action('wp_ajax_wpsecure_scan_theme', [$this, 'scan_theme']);
        add_action('wp_ajax_wpsecure_scan_core', [$this, 'scan_core']);
        add_action('wp_ajax_wpsecure_scan_files', [$this, 'scan_files']);
    }

    public function menu() {
        add_menu_page(
            'WP Secure',
            'WP Secure',
            'manage_options',
            'wp-secure',
            [$this, 'page'],
            'dashicons-shield'
        );
    }

    public function page() {
        ?>
        <div class="wrap">
            <h1>WP Secure Scanner</h1>
            <button id="start-scan" class="button button-primary">Start Scan</button>
            <div id="scan-results"></div>
        </div>
        <?php
    }

    public function scripts($hook) {
        if ($hook !== 'toplevel_page_wp-secure') return;

        wp_enqueue_script('wpsecure-js', plugin_dir_url(__FILE__) . 'script.js', ['jquery'], null, true);

        wp_localize_script('wpsecure-js', 'wpsecure_ajax', [
            'ajax_url' => admin_url('admin-ajax.php'),
            'nonce' => wp_create_nonce('wpsecure_nonce')
        ]);
    }

    public function get_plugins() {
        check_ajax_referer('wpsecure_nonce', 'nonce');

        include_once ABSPATH . 'wp-admin/includes/plugin.php';

        $plugins = get_option('active_plugins');
        $data = [];

        foreach ($plugins as $plugin) {
            $plugin_data = get_plugin_data(WP_PLUGIN_DIR . '/' . $plugin);

            $data[] = [
                'path' => $plugin,
                'slug' => explode('/', $plugin)[0],
                'version' => $plugin_data['Version'],
                'name' => $plugin_data['Name']
            ];
        }

        wp_send_json_success($data);
    }

    public function scan_plugin() {
        check_ajax_referer('wpsecure_nonce', 'nonce');

        $slug = sanitize_text_field($_POST['slug']);
        $version = sanitize_text_field($_POST['version']);

        $url = "https://wpscan.com/api/v3/plugins/$slug";

        $response = wp_remote_get($url, [
            'headers' => [
                'Authorization' => 'Token token=' . $this->api_key
            ]
        ]);

        if (is_wp_error($response)) {
            wp_send_json_error('API error');
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (empty($body[$slug])) {
            wp_send_json_success([
                'plugin' => $slug,
                'status' => 'No Data',
                'risk' => 0
            ]);
        }

        $plugin_data = $body[$slug];
        $vulnerabilities = $plugin_data['vulnerabilities'] ?? [];

        $real_vulns = [];

        foreach ($vulnerabilities as $vuln) {
            if (!empty($vuln['fixed_in'])) {
                if (version_compare($version, $vuln['fixed_in'], '<')) {
                    $real_vulns[] = $vuln;
                }
            }
        }

        $active = count($real_vulns);

        if ($active == 0) {
            $status = 'Safe';
            $risk = 0;
        } elseif ($active <= 2) {
            $status = 'Low Risk';
            $risk = 30;
        } elseif ($active <= 5) {
            $status = 'Medium Risk';
            $risk = 60;
        } else {
            $status = 'High Risk';
            $risk = 90;
        }

        $latest_version = $plugin_data['latest_version'] ?? '';
        $needs_update = version_compare($version, $latest_version, '<');

        wp_send_json_success([
            'plugin' => $slug,
            'current_version' => $version,
            'latest_version' => $latest_version,
            'active_vulnerabilities' => $active,
            'status' => $status,
            'risk_score' => $risk,
            'needs_update' => $needs_update,
        ]);
    }

    private function call_api($endpoint) {

        $url = "https://wpscan.com/api/v3/" . $endpoint;

        $response = wp_remote_get($url, [
            'headers' => [
                'Authorization' => 'Token token=' . $this->api_key
            ]
        ]);

        if (is_wp_error($response)) return [];

        return json_decode(wp_remote_retrieve_body($response), true);
    }

    public function scan_files() {

        check_ajax_referer('wpsecure_nonce', 'nonce');

        $suspicious_patterns = [
            'eval(',
            'base64_decode(',
            'exec(',
            'shell_exec(',
            'gzinflate('
        ];

        $directory = ABSPATH; 
        $results = [];

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory)
        );

        foreach ($iterator as $file) {

            if ($file->isFile() && $file->getExtension() === 'php') {

                $content = file_get_contents($file->getPathname());

                foreach ($suspicious_patterns as $pattern) {
                    if (strpos($content, $pattern) !== false) {

                        $results[] = [
                            'file' => $file->getPathname(),
                            'pattern' => $pattern
                        ];

                        break;
                    }
                }
            }
        }

        wp_send_json_success($results);
}

   public function scan_theme() {

        check_ajax_referer('wpsecure_nonce', 'nonce');

        $theme = wp_get_theme();

        $slug = $theme->get_stylesheet();
        $version = $theme->get('Version');

        // ✅ Correct API call
        $body = $this->call_api("themes/$slug");

        if (!$body || empty($body[$slug])) {
            wp_send_json_success([
                'theme' => $slug,
                'version' => $version,
                'status' => 'No Data',
                'issues' => 0
            ]);
        }

        $theme_data = $body[$slug];
        error_log(print_r($body, true));

        // ✅ Use common processor
        $processed = $this->process_vulnerabilities($theme_data, $slug, $version);

        wp_send_json_success([
            'theme' => $slug,
            'version' => $version,
            'status' => $processed['status'],
            'issues' => $processed['active_vulnerabilities']
        ]);
    }
    
    public function scan_core() {

        check_ajax_referer('wpsecure_nonce', 'nonce');

        global $wp_version;

        $body = $this->call_api("wordpresses/$wp_version");

        $vulns = $body[$wp_version]['vulnerabilities'] ?? [];

        wp_send_json_success([
            'version' => $wp_version,
            'issues' => count($vulns),
            'status' => empty($vulns) ? 'Safe' : 'Vulnerable'
        ]);
    }

   private function process_vulnerabilities($plugin_data, $slug, $version) {

        $vulnerabilities = $plugin_data['vulnerabilities'] ?? [];
        $real_vulns = [];

        foreach ($vulnerabilities as $vuln) {
            if (!empty($vuln['fixed_in']) && version_compare($version, $vuln['fixed_in'], '<')) {
                $real_vulns[] = $vuln;
            }
        }

        $active = count($real_vulns);

        if ($active == 0) {
            $status = 'Safe';
            $risk = 0;
        } elseif ($active <= 2) {
            $status = 'Low Risk';
            $risk = 30;
        } elseif ($active <= 5) {
            $status = 'Medium Risk';
            $risk = 60;
        } else {
            $status = 'High Risk';
            $risk = 90;
        }

        return [
            'active_vulnerabilities' => $active,
            'status' => $status,
            'risk_score' => $risk
        ];
    }
}

new WPSecure(); 
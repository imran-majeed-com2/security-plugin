jQuery(document).ready(function ($) {

    let isScanning = false;

    $('#start-scan').on('click', function () {

        if (isScanning) return;
        isScanning = true;

        $('#scan-results').html('<h3>Starting Full Scan...</h3>'); 
        function scanCore(next) {

            $('#scan-results').append('<h4>🔍 Scanning WordPress Core...</h4>');

            $.post(wpsecure_ajax.ajax_url, {
                action: 'wpsecure_scan_core',
                nonce: wpsecure_ajax.nonce
            })
            .done(function (res) {

                if (res.success) {
                    let d = res.data;

                    let color = d.status === 'Safe' ? 'green' : 'red';

                    $('#scan-results').append(`
                        <div style="border:1px solid #ddd; padding:10px; margin:10px 0;">
                            <strong>WordPress Core</strong><br>
                            Version: ${d.version} <br>
                            Issues: ${d.issues} <br>
                            <span style="color:${color};">${d.status}</span>
                        </div>
                    `);
                }

            })
            .fail(function () {
                $('#scan-results').append('<p style="color:red;">Error scanning WordPress Core</p>');
            })
            .always(function () {
                next(); 
            });
        }

        function scanTheme(next) {

            $('#scan-results').append('<h4>🎨 Scanning Theme...</h4>');

            $.post(wpsecure_ajax.ajax_url, {
                action: 'wpsecure_scan_theme',
                nonce: wpsecure_ajax.nonce
            })
            .done(function (res) {

                if (res.success) {
                    let d = res.data;

                    let color = d.status === 'Safe' ? 'green' : 'red';

                    $('#scan-results').append(`
                        <div style="border:1px solid #ddd; padding:10px; margin:10px 0;">
                            <strong>Theme: ${d.theme}</strong><br>
                            Version: ${d.version} <br>
                            Issues: ${d.issues} <br>
                            <span style="color:${color};">${d.status}</span>
                        </div>
                    `);
                }

            })
            .fail(function () {
                $('#scan-results').append('<p style="color:red;">Error scanning theme</p>');
            })
            .always(function () {
                next(); 
            });
        }

       
    
        function scanPlugins() {

            $('#scan-results').append('<h4>🔌 Scanning Plugins...</h4>');

            $.post(wpsecure_ajax.ajax_url, {
                action: 'wpsecure_get_plugins',
                nonce: wpsecure_ajax.nonce
            }, function (response) {

                if (!response.success) {
                    isScanning = false;
                    return;
                }

                let plugins = response.data;
                let index = 0;

                function scanNextPlugin() {

                    if (index >= plugins.length) {
                        $('#scan-results').append('<h3>✅ Full Scan Completed</h3>');
                        isScanning = false;
                        return;
                    }

                    let plugin = plugins[index];

                    $('#scan-results').append(`<p>Scanning: ${plugin.name}</p>`);

                    $.post(wpsecure_ajax.ajax_url, {
                        action: 'wpsecure_scan_plugin',
                        nonce: wpsecure_ajax.nonce,
                        slug: plugin.slug,
                        version: plugin.version
                    })
                    .done(function (res) {

                        if (res.success) {

                            let d = res.data;

                            let color = 'green';
                            if (d.status === 'Medium Risk') color = 'orange';
                            if (d.status === 'High Risk') color = 'red';

                            let updateText = d.needs_update ? '⚠ Update Available' : '✔ Up to date';

                            $('#scan-results').append(`
                                <div style="border:1px solid #ddd; padding:10px; margin:10px 0;">
                                    <strong>${plugin.name}</strong><br>
                                    Version: ${d.current_version} <br>
                                    Issues: ${d.active_vulnerabilities} <br>
                                    <span style="color:${color};">${d.status}</span><br>
                                    ${updateText}
                                </div>
                            `);
                        }

                    })
                    .fail(function () {
                        $('#scan-results').append(`<p style="color:red;">Error scanning ${plugin.name}</p>`);
                    })
                    .always(function () {
                        index++;

                        // delay for API safety
                        setTimeout(scanNextPlugin, 800);
                    });
                }

                scanNextPlugin();
            });
        }

        function scanFiles(next) {

            $('#scan-results').append('<h4>📁 Scanning Files...</h4>');

            $.post(wpsecure_ajax.ajax_url, {
                action: 'wpsecure_scan_files',
                nonce: wpsecure_ajax.nonce
            })
            .done(function (res) {

                if (res.success && res.data.length > 0) {

                    res.data.forEach(f => {
                        $('#scan-results').append(`
                            <div style="color:red;">
                                ⚠ Suspicious File: ${f.file}<br>
                                Pattern: ${f.pattern}
                            </div>
                        `);
                    });

                } else {
                    $('#scan-results').append('<p>✔ No suspicious files found</p>');
                }

            })
            .always(function () {
                next();
            });
        }

      

       scanCore(function () {
            scanTheme(function () {
                scanFiles(function () {
                    scanPlugins();
                });
            });
        });

    });

});
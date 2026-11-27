<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=true; section>
    <#if section = "header">
        Checking your device…
    <#elseif section = "form">
        <form id="device-check-form" action="${url.loginAction}" method="post">
            <input type="hidden" id="deviceState" name="deviceState" value=""/>
            <noscript>
                <p>JavaScript is required to check your device.</p>
                <input type="submit" value="Continue"/>
            </noscript>
            <#if deviceCheckFailed??>
                <input type="submit" value="Try again"/>
            </#if>
        </form>

        <script>
            (async function () {
                // Collect whatever device state you need here. Keep it JSON-serialisable.
                async function collectDeviceState() {
                    var nav = window.navigator || {};
                    var state = {
                        userAgent: nav.userAgent,
                        platform: nav.platform,
                        language: nav.language,
                        languages: nav.languages,
                        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                        screen: { width: screen.width, height: screen.height, pixelRatio: window.devicePixelRatio },
                        hardwareConcurrency: nav.hardwareConcurrency,
                        deviceMemory: nav.deviceMemory,
                        touchPoints: nav.maxTouchPoints,
                        cookiesEnabled: nav.cookieEnabled,
                        collectedAt: new Date().toISOString()
                    };
                    // Example of an async check you could add:
                    // if (nav.userAgentData) {
                    //     state.uaData = await nav.userAgentData.getHighEntropyValues(["platformVersion", "model"]);
                    // }
                    return state;
                }

                var form = document.getElementById("device-check-form");
                <#if deviceProveUrl??>
                // Device host asks for the device cert during TLS; the server records it against this login's nonce.
                // cors (not no-cors): Keycloak's no-referrer policy would make a no-cors POST send "Origin: null".
                // A failure just means "no device cert".
                try {
                    await fetch("${deviceProveUrl}", {
                        method: "POST", mode: "cors", credentials: "include", signal: AbortSignal.timeout(60000) // long enough for the user to answer the cert picker
                    });
                } catch (e) { /* no cert / cancelled picker / host down */ }
                </#if>
                try {
                    document.getElementById("deviceState").value = JSON.stringify(await collectDeviceState());
                } catch (e) {
                    document.getElementById("deviceState").value = JSON.stringify({ error: String(e) });
                }
                <#-- On the error screen, wait for the user instead of looping. -->
                <#if !deviceCheckFailed??>
                form.submit();
                </#if>
            })();
        </script>
    </#if>
</@layout.registrationLayout>

document.addEventListener("DOMContentLoaded", () => {
    const overlay = document.getElementById("loadingOverlay");
    const message = document.getElementById("loadingMessage");

    const actionMessages = {
        "/run/trueaegis_validate": "Running safe validation checks against the latest NetSniper findings...",
        "/run/trueaegis_report": "Generating Markdown and PDF reports. This can take a little while...",
        "/run/trueaegis_snapshot": "Saving a TrueAegis platform snapshot...",
        "/run/trueaegis_delta": "Comparing the latest snapshots and building a delta report...",
        "/run/trueaegis_dashboard": "Rendering the terminal dashboard output...",
        "/run/netsniper": "Launching NetSniper. Interactive terminal actions may not return through the browser."
    };

    document.querySelectorAll("form[action^='/run/']").forEach((form) => {
        form.addEventListener("submit", () => {
            const submitButton = form.querySelector("button[type='submit']");
            const action = form.getAttribute("action");

            if (message) {
                message.textContent = actionMessages[action] || "Running selected TrueAegis action...";
            }

            if (submitButton) {
                submitButton.classList.add("is-loading");
                submitButton.disabled = true;
                submitButton.textContent = "Running...";
            }

            if (overlay) {
                overlay.classList.remove("hidden");
            }
        });
    });
});

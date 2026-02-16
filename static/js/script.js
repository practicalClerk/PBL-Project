async function checkPhishing() {
    let userURL = document.getElementById("urlInput").value.trim();

    if (userURL === "") {
        alert("❌ Please enter a valid URL.");
        return;
    }

    try {
        let response = await fetch("phishing_dataset.json");
        let data = await response.json();

        let formattedURL = userURL.replace("https://", "").replace("http://", "").replace("www.", "").toLowerCase();
        let isPhishing = data.phishing_urls.some(phishURL =>
            formattedURL.includes(phishURL.replace("[.]", "."))
        );

        let resultElement = document.getElementById("result");

        if (isPhishing) {
            resultElement.innerHTML = `<span style="color: red; font-weight: bold;">🚨 Warning! This website is flagged as phishing.</span>`;
        } else {
            resultElement.innerHTML = `<span style="color: green; font-weight: bold;">✅ This website might be safe to go for, but be cautious.</span>`;
        }

    } catch (error) {
        console.error("Error loading phishing data:", error);
        alert("⚠️ Could not load phishing database.");
    }
}

function goBack() {
    window.history.back();
}

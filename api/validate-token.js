async function checkSubscription() {
    const SESSION_KEY = 'eta_extension_active_session';

    try {
        console.log("===== STEP 1: Get current issuer data =====");
        const currentIssuerData = await getIssuerFullData();
        if (!currentIssuerData || !currentIssuerData.id) return null;
        const currentRin = currentIssuerData.id;
        console.log("Current RIN:", currentRin);

        console.log("===== STEP 2: Check stored session =====");
        const storedSessionRaw = sessionStorage.getItem(SESSION_KEY);
        if (storedSessionRaw) {
            const storedSession = JSON.parse(storedSessionRaw);
            console.log("Stored session found:", storedSession);

            if (storedSession.rin === currentRin && storedSession.token) {
                const validationResponse = await fetch(
                    'https://subscriptions-tan-two.vercel.app/api/validate-token',
                    {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${storedSession.token}`
                        }
                    }
                );
                console.log("Token response status:", validationResponse.status);
                const validationResult = await validationResponse.json();
                console.log("Token request result:", validationResult);

                if (validationResponse.ok && validationResult.success) {
                    return { seller: currentIssuerData, devices: [] };
                }
            }
        } else {
            console.log("No stored session found");
        }

        console.log("===== STEP 3: Request new token =====");
        sessionStorage.removeItem(SESSION_KEY);

        const tokenResponse = await fetch(
            'https://subscriptions-tan-two.vercel.app/api/check-subscription',
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ rin: currentRin })
            }
        );
        console.log("Token response status:", tokenResponse.status);
        const tokenResult = await tokenResponse.json();
        console.log("Token request result:", tokenResult);

        if (!tokenResult.success || !tokenResult.session_token) return null;

        const newSession = { rin: currentRin, token: tokenResult.session_token };
        sessionStorage.setItem(SESSION_KEY, JSON.stringify(newSession));

        return { seller: currentIssuerData, devices: [] };

    } catch (error) {
        console.error("Subscription check ERROR:", error);
        sessionStorage.removeItem(SESSION_KEY);
        return null;
    }
}

// Google Authentication handling
function initializeGoogleAuth(dotNetReference) {
    // Load Google Sign-In API
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    document.head.appendChild(script);

    // Handle Google Sign-In callback
    window.handleGoogleSignIn = async (response) => {
        try {
            const credential = response.credential;

            // Call your API endpoint with the Google ID token
            const result = await fetch('/api/GoogleAuth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ idToken: credential })
            });

            const data = await result.json();

            if (result.ok && data.successful) {
                await dotNetReference.invokeMethodAsync('OnGoogleLoginSuccess', data.token);
            } else {
                await dotNetReference.invokeMethodAsync('OnGoogleLoginError', data.error || 'Đăng nhập thất bại');
            }
        } catch (error) {
            await dotNetReference.invokeMethodAsync('OnGoogleLoginError', error.message);
        }
    };
}
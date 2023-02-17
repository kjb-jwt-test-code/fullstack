// Service handling all details related to JWT and Basic Authentication.
import axios from 'axios';
import cookies from 'react-cookies'
export const USER_NAME_SESSION_ATTRIBUTE_NAME = 'authenticatedUser'
class AuthenticationService {
    executeJwtAuthenticationService(username, password) {
        return axios.post('/api/authenticate',
            { username, password }
        );
    }

    registerSuccessfulLoginForJwt(username, token) {
        sessionStorage.setItem(USER_NAME_SESSION_ATTRIBUTE_NAME, username);
        this.setupAxiosInterceptors(token);
    }

    // sets up the axios interceptor to add the authorization token on every subsequent REST API call. config.headers.authorization = token
    setupAxiosInterceptors(token) {
        console.log(token);
        axios.defaults.headers.common["Authorization"] = `Bearer ${token.token}`;
        cookies.save('token', '${token.token}');

        // axios.interceptors.request.use(
        //     config => {
        //         // 요청마다 쿠키에 저장된 토큰을 서버에 전송
        //         config.withCredentials = true;
        //         return config;
        //     }
        // )
    }

    isUserLoggedIn() {
        let user = sessionStorage.getItem(USER_NAME_SESSION_ATTRIBUTE_NAME);
        if (user === null) return false;
        return true;
    }

    logout() {
        sessionStorage.removeItem(USER_NAME_SESSION_ATTRIBUTE_NAME);
    }
}

export default new AuthenticationService();
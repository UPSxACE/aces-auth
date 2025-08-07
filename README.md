# Ace's Auth Service
[![version](https://img.shields.io/github/v/tag/upsxace/aces-auth-service?label=version)](https://github.com/upsxace/aces-auth-service/releases)

A lightweight identity and access platform for modern web and backend applications — inspired by Auth0, Okta, and Clerk.

> 🔐 Plug-and-play OAuth sign-in, roles, and permissions for your app — with first-class SDKs for Next.js and Spring Boot.

Standards-based authentication and authorization using OAuth 2.0 and OpenID Connect — without the boilerplate. Register your app, drop in the SDK, and go.

## 🚧 Status
This project is currently under active development. While the core functionality is in place, the platform and SDKs are evolving rapidly. Expect improvements, new features, and refinements over time.

## 🧭 Index
* [📡 API Endpoints](#📡-api-endpoints)
  * [Authentication](#authentication)
  * [Apps](#apps)
  * [Info](#info)
* [📦 Tech Stack](#📦-tech-stack)
* [🤝 Contributing](#🤝-contributing)
* [📜 License](#📜-license)
* [✨ Acknowledgments](#✨-acknowledgments)



> 📚 The README will be expanded soon with full documentation, usage examples, and integration guides.

## 📡 API Endpoints

### Authentication
| Method | URL                    | Request Params                 | Request Body                    | Description |
| ------ | ---------------------- | ------------------------------ | ------------------------------- | ----------- |
| POST   | /auth/register         | —                              | request: RegisterByEmailRequest | Register with username, email, name, password         |
| POST   | /auth/login            | —                              | request: LoginRequest           | Username/password login, returns JWT         |
| POST   | /auth/oauth/{provider} | provider: string (path)        | request: OAuthLoginRequest      | Accepts OAuth token/code, returns JWT         |
| GET    | /auth/me               | —                              | —                               | Returns current user info         |
| GET    | /auth/session          | refreshToken?: string (cookie) | —                               | Retrieves session information associated with the provided refresh token cookie         |
| POST   | /auth/refresh          | refreshToken: string (cookie)  | —                               | Refresh JWT         |
| POST   | /auth/logout           | refreshToken?: string (cookie) | —                               | Delete refresh token cookie and blacklist refresh token         |

### Apps
| Method | URL                     | Request Params                     | Request Body             | Description |
| ------ | ----------------------- | ---------------------------------- | ------------------------ | ----------- |
| POST   | /apps                   | —                                  | request: WriteAppRequest | Create app         |
| GET    | /apps                   | —                                  | —                        | Get all apps from authenticated user         |
| GET    | /apps/{id}              | id: UUID (path)                    | —                        | Get app info         |
| PUT    | /apps/{id}              | id: UUID (path)                    | request: WriteAppRequest | Update app info         |
| DELETE | /apps/{id}              | id: UUID (path)                    | —                        | Delete app         |
| POST   | /apps/{id}/reset-secret | id: UUID (path)                    | —                        | Resets app's client secret         |
| POST   | /apps/consent           | client\_id: string, scopes: string | —                        | Grant consent to specified scopes to specified app         |
| GET | /apps/connections | — | — | Get information about all apps that are connected to authenticated user |
| DELETE | /apps/connections | client_id: string | — | Disconnect account from an app by the specified client id |

### Info
| Method | URL       | Request Params                             | Request Body | Description |
| ------ | --------- | ------------------------------------------ | ------------ | ----------- |
| GET    | /info/app | client\_id: string, check\_scopes?: string | —            | Retrieves public information about an app by its client ID, optionally checking if the app has the specified scopes.         |


## 📦 Tech Stack
- Java 21
- Maven
- Spring Boot
- Spring Boot Security
- Spring Boot Authorization Server
- Postgres

## 🤝 Contributing
Contributions are welcome! Please open an issue or pull request.

## 📜 License
This project is licensed under the [MIT License](LICENSE).

## ✨ Acknowledgments
- Built with ❤️ by Ace
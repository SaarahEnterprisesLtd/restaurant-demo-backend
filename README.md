🍽️ Saarah Eats – Restaurant Ordering App

Saarah Eats is a full-stack restaurant ordering platform with guest checkout, user accounts, admin management, and Stripe payments.
The app is production-ready, deployed on Vercel + DigitalOcean, and designed with clean UX and secure authentication.

🚀 Live Demo

Frontend: https://restaurant-demo-frontend.vercel.app

Backend API: https://saarah-eats-9gof7.ondigitalocean.app

🧰 Tech Stack
Frontend

React + Vite

Tailwind CSS

React Router

Axios (with credentials)

Stripe Elements

Deployed on Vercel

Backend

Node.js + Express (CommonJS)

MySQL (DigitalOcean Managed DB)

JWT authentication (httpOnly cookies)

Stripe Payments

Cloudinary (menu image uploads)

Hosted on DigitalOcean App Platform

🔐 Authentication & Security

JWT stored in httpOnly cookies

Cross-domain cookies configured with:

SameSite=None

Secure=true

CORS allowlist via environment variables

Role-based access control:

Guest

User

Admin

🧑‍🍳 Core Features
Guest & User

Browse menu (all items always visible)

Sticky category navigation (desktop + mobile)

Cart with quantity controls

Guest checkout (no account required)

Stripe payment integration

Order tracking with live status updates

Order cancellation (before preparation)

Clean retry flow for failed payments

Admin

Admin-only dashboard

Menu CRUD (create / edit / delete items)

Image uploads via Cloudinary

Category management

View all orders

Update order status:

placed → preparing → ready → out_for_delivery → delivered

Cancel orders when applicable

🛒 Cart System

Users: cart stored in MySQL

Guests: cart stored server-side via secure httpOnly cookie

Automatic cart sync on login

Cart cleared automatically after successful payment

💳 Payments (Stripe)

Stripe Payment Intents

Secure checkout with Stripe Elements

Test card support (no real card required)

Idempotent order confirmation

Safe retry flow without duplicate orders

Orders are only finalized after payment success

📦 Project Structure
frontend/
 ├─ src/
 │  ├─ pages/
 │  ├─ components/
 │  ├─ context/
 │  ├─ api/
 │  └─ App.jsx
 └─ vite.config.js

backend/
 ├─ index.js
 ├─ routes/
 ├─ middleware/
 └─ package.json

⚙️ Environment Variables
Frontend (.env)
VITE_API_URL=https://saarah-eats-9gof7.ondigitalocean.app
VITE_STRIPE_PUBLISHABLE_KEY=pk_test_xxx

Backend (.env)
PORT=8080
NODE_ENV=production

DB_HOST=...
DB_USER=...
DB_PASSWORD=...
DB_NAME=...

JWT_SECRET=your_secret
JWT_EXPIRES_IN=15m

STRIPE_SECRET_KEY=sk_test_xxx

CORS_ORIGIN=https://restaurant-demo-frontend.vercel.app

CLOUDINARY_CLOUD_NAME=...
CLOUDINARY_API_KEY=...
CLOUDINARY_API_SECRET=...

🛠️ Local Development
Backend
cd backend
npm install
npm run dev

Frontend
cd frontend
npm install
npm run dev

✅ Deployment Notes

Frontend deployed on Vercel

Backend deployed on DigitalOcean App Platform

Managed MySQL with TLS enabled

No Vite proxy used in production

Environment-based CORS handling

📈 Future Improvements

WebSocket order notifications

Admin analytics dashboard

Delivery fee & tax rules

Refund support via Stripe

Mobile app version

👨‍💻 Author

Built with care by Saravanan
Full-stack developer focused on scalable, production-ready applications.

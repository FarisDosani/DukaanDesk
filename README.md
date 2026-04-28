# DukaanDesk

A comprehensive, full-stack retail and inventory management system designed to handle the core operations of a storefront. DukaanDesk bridges a clean, responsive web frontend with a highly structured relational database architecture, utilizing advanced SQL concepts like stored procedures, triggers, and analytical views.

## 🌟 Key Features
* **User Authentication:** Secure login and signup flows (`login.html`, `signup.html`) to manage access to the system.
* **Storefront Interface:** A responsive store interface (`store.html`, `index.html`) for managing active inventory.
* **Admin Dashboard:** A central control panel (`dashboard.html`, `summary.html`) for viewing business insights.
* **Advanced Database Logic:** Custom SQL triggers and stored procedures (`2_Logic.sql`) automate business rules (e.g., stock depletion on sale, cart validations).
* **Automated Reporting:** Pre-built SQL views and queries (`4_Reports.sql`) for generating analytics, such as daily sales and low-stock alerts.
* **Rapid Teardown & Testing:** Includes scripts to instantly reset the database (`reset.sql`) and seed it with mock data (`3_DataTesting.sql`).

## 🛠️ Tech Stack
* **Frontend:** HTML5, CSS3 (`styles.css`)
* **Backend:** Python (`app.py`, dependencies in `requirements.txt`)
* **Database:** SQL (MySQL)

## 📁 Repository Structure
The project is modularized into distinct frontend and backend layers:

**Frontend (Client)**
* `index.html` / `store.html`: Main user-facing store pages.
* `login.html` / `signup.html`: Authentication views.
* `dashboard.html` / `summary.html`: Administrative reporting views.
* `styles.css`: Global stylesheet for the application.

**Backend & Database (Server)**
* `app.py`: The main Python application/API server.
* `1_Schema.sql`: Defines tables, primary/foreign keys, and data types.
* `2_Logic.sql`: Contains the business logic, stored procedures, and triggers.
* `3_DataTesting.sql`: Seeds the database with mock data.
* `4_Reports.sql`: Generates analytical reports and complex join views.
* `reset.sql`: Drops existing tables and resets the database state.

## 🚀 How to Run Locally

### 1. Database Setup
1. Clone the repository:
   ```bash
   git clone [https://github.com/FarisDosani/DukaanDesk.git](https://github.com/FarisDosani/DukaanDesk.git)

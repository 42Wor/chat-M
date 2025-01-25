# Project: User Management and Chat Web Application

This project is a Python-based web application designed to handle user registration, login, and real-time chat functionality. It provides a basic platform for users to interact and communicate.

## Project Structure

The project is organized as follows:

- **`database.py`**: Contains logic for interacting with the database, including functions for user authentication, data storage, and retrieval.
- **`main.py`**: The main application entry point. This file initializes the Flask application, defines routes, and manages the core application logic.
- **`requirements.txt`**: Lists all Python dependencies required to run the project. These can be installed using `pip`.
- **`users.dm`**: This file likely stores user information. *Note: Storing user data in this manner is generally not recommended for production systems and can be insecure. Consider using a database system instead.*
- **`maazDB/`**: A directory that likely contains database-related configuration files or database files (e.g., SQLite database).
- **`templates/`**: Contains all HTML templates for rendering the user interface.
    - **`chat.html`**:  Template for the real-time chat interface.
    - **`home.html`**: Template for the main dashboard or home page after login.
    - **`login.html`**: Template for the user login form.
    - **`register.html`**: Template for the user registration form.
    - **`1.css`**:  CSS stylesheet for styling the HTML templates.

## Getting Started

To run this application:

1. **Install Dependencies:**
   ```bash
   pip install -r requirements.txt
   python3 main.py

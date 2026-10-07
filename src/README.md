# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Sign up for activities

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python -m uvicorn app:app --reload
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.

## Teacher access

Students can view activities and participants without signing in. Only teachers can sign up or unregister students.

Create a local teacher account from the `src` directory:

```
python manage_teachers.py
```

This writes a `teachers.json` file containing a salted PBKDF2 password hash. The file is ignored by Git. To use another account-file path, set `TEACHER_ACCOUNTS_FILE` for both the app and the account-management command.

The app signs teacher sessions with a random secret when `TEACHER_SESSION_SECRET` is unset, which invalidates sessions when the process restarts. Set a stable secret in the environment when running multiple workers or when sessions should survive restarts.

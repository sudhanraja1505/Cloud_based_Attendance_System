# Cloud-Based Student Attendance System

## Run locally (Windows / Mac / Linux)
    python -m venv venv
    venv\Scripts\activate          # Mac/Linux: source venv/bin/activate
    python -m pip install -r requirements.txt
    python app.py                  # open http://localhost:5000

## How it works
1. A teacher registers, creates a class and shares its join code.
2. Students register (role: Student) and join the class with that code.
3. For each lecture the teacher clicks "Start attendance". A 6-digit code appears and stays valid for the chosen minutes.
4. Students enter the code to mark themselves present. Anyone who doesn't is absent.
5. The teacher can tick/untick students in a session, view the class report (attended / total / %), and download it as CSV.
6. Students see their attendance percentage per class, with a warning below 75% (change MIN_PERCENT in app.py).

## Deploy to the cloud
- Set SECRET_KEY and DB_PATH
- Linux: pip install gunicorn, run `gunicorn app:app`. Windows: pip install waitress, run `waitress-serve app:app`
- Use PostgreSQL (AWS RDS) and HTTPS in production; move the code-attempt limiter to Redis if you run several servers
- Hosting options: AWS Elastic Beanstalk, EC2 + Nginx, Render, Railway

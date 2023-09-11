from flask import Flask, request, jsonify, render_template,session,redirect,url_for, flash
from flask_mysqldb import MySQL
import logging
from datetime import datetime, timedelta
import traceback  
from werkzeug.security import generate_password_hash,check_password_hash
import jwt
from functools import wraps


SECRET_KEY = "a8368e76f2d161f272b7daf3f98a8ec3"

logging.basicConfig(level=logging.DEBUG)



# Initialize Flask and MySQL
app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['MYSQL_HOST'] = ''
app.config['MYSQL_USER'] = ''
app.config['MYSQL_PASSWORD'] = ''  
app.config['MYSQL_DB'] = ''  


mysql = MySQL(app)

@app.route('/')
def index():
    if 'user_id' not in session:
        # User not logged in, redirect to login page
        return redirect(url_for('login_page'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT username, role FROM users WHERE id = %s", [user_id])
    user = cursor.fetchone()

    if not user:
        cursor.close()
        return "Error: User not found", 500

    username = user[0]
    role = user[1]

    students = []
    if role == 'student':
        # Fetch only the student's details
        cursor.execute("SELECT id, username FROM users WHERE id = %s", [user_id])
        students = cursor.fetchall()
    elif role == 'staff':
        # Fetch all students assigned to the staff member
        cursor.execute('''
            SELECT u.id, u.username 
            FROM users u
            LEFT JOIN staff_student_relationship ssr ON u.id = ssr.student_id 
            WHERE ssr.staff_id = %s OR u.id = %s
        ''', (user_id, user_id))
        students = cursor.fetchall()

    # Fetch tasks of the logged-in user along with assigned_by_name
    cursor.execute('''
        SELECT tasks.id, tasks.text, tasks.dueDate, tasks.estimated_time, tasks.description, users.username as assigned_by_name
        FROM tasks 
        JOIN users ON tasks.assigned_by = users.id
        WHERE tasks.user_id = %s
    ''', [user_id])
    tasks = cursor.fetchall()
    
    cursor.close()

    return render_template('task_management_advanced.html', username=username, students=students, tasks=tasks, role=role)




@app.route('/login')
def login_page():
    return render_template('login_page.html')
@app.route('/logout')
def logout():
    # Remove user_id from session
    session.pop('user_id', None)
    return redirect(url_for('login_page'))

@app.route('/register')
def register_page():
    return render_template('registration_page.html')

# Add the requires_auth function here
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        # Replace 'admin' and 'secret' with your desired username and password
        if not auth or not (auth.username == 'admin' and auth.password == 'secret'):
            return 'Login Required', 401, {'WWW-Authenticate': 'Basic realm="Login required"'}
        return f(*args, **kwargs)
    return decorated
@app.route('/api/tasks', methods=['GET'])
@app.route('/api/tasks/<int:selected_user_id>', methods=['GET'])
def get_tasks(selected_user_id=None):
    try:
        cursor = mysql.connection.cursor()

        if selected_user_id:
            cursor.execute("""
                SELECT tasks.id, tasks.text, tasks.dueDate, tasks.estimated_time, tasks.description, users.username 
                FROM tasks 
                JOIN users ON tasks.assigned_by = users.id
                WHERE tasks.user_id = %s
            """, [selected_user_id])
        else:
            user_id = session['user_id']
            cursor.execute("""
                SELECT tasks.id, tasks.text, tasks.dueDate, tasks.estimated_time, tasks.description, users.username 
                FROM tasks 
                JOIN users ON tasks.assigned_by = users.id
                WHERE tasks.user_id = %s
            """, [user_id])

        tasks = cursor.fetchall()
        cursor.close()

        tasks_list = []
        for task in tasks:
            task_dict = {
                "id": task[0],
                "text": task[1],
                "dueDate": task[2].strftime('%Y-%m-%d %H:%M:%S'),
                "estimated_time": task[3],
                "description": task[4].replace('\n', '<br>'),
                "assigned_by_name": task[5]
            }
            logging.debug(f"Task Data: {task_dict}")  # Log the task data for inspection
            tasks_list.append(task_dict)
            
        return jsonify(tasks_list)

    except Exception as e:
        logging.error(f"An error occurred in get_tasks: {e}")
        logging.error(traceback.format_exc())  # Log the full traceback
        return jsonify({"error": "An internal error occurred"}), 500


@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    try:
        cursor = mysql.connection.cursor()
        cursor.execute("DELETE FROM tasks WHERE id = %s", [task_id])
        mysql.connection.commit()
        affected_rows = cursor.rowcount
        cursor.close()

        if affected_rows == 1:
            return jsonify({"message": "Task deleted successfully"}), 200
        else:
            return jsonify({"error": "Delete failed"}), 500

    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/tasks', methods=['POST'])
def add_task():
        data = request.json
        text = data.get('text')
        dueDateTime = data.get('dueDate')
        dueDateTime = datetime.fromisoformat(dueDateTime).strftime('%Y-%m-%d %H:%M:%S')
        estimated_time = data.get('estimated_time')
        description = data.get('description')
        assigned_by = session['user_id']
        assigned_to = data.get('user_id')

        cursor = mysql.connection.cursor()
        cursor.execute(
            "INSERT INTO tasks (text, dueDate, estimated_time, description, user_id, assigned_by) VALUES (%s, %s, %s, %s, %s, %s)", 
            (text, dueDateTime, estimated_time, description, assigned_to, assigned_by)
        )
        mysql.connection.commit()

        affected_rows = cursor.rowcount
        last_row_id = cursor.lastrowid
        cursor.close()

        if affected_rows == 1:
            return jsonify({"id": last_row_id}), 201
        else:
            return jsonify({"error": "Insert failed"}), 500



@app.route('/api/register', methods=['POST'])
def register():
    # Get data from form fields
    fullname = request.form['fullname']
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    confirmpassword = request.form['confirmpassword']

    # Ensure passwords match
    if password != confirmpassword:
        return "Passwords do not match!", 400

    # Hash the password before storing it
    hashed_password = generate_password_hash(password, method='sha256')

    # Write to the database
    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)", (username, hashed_password, email))
    mysql.connection.commit()
    cursor.close()


    # After successful registration, redirect to the login page
    return redirect(url_for('login_page'))

@app.route('/admin')
@requires_auth
def admin_dashboard():
    cursor = mysql.connection.cursor()

    # Fetching all users with pending approval
    cursor.execute("SELECT id, username, email FROM users WHERE account_status = 'pending'")
    pending_users = cursor.fetchall()
    
    # Fetching all staff members
    cursor.execute("SELECT id, username FROM users WHERE role = 'staff'")
    staff_members = cursor.fetchall()

    # Fetching all student members
    cursor.execute("SELECT id, username FROM users WHERE role = 'student'")
    students = cursor.fetchall()

    # Fetching current assignments
    cursor.execute("""
        SELECT s.id AS staff_id, s.username AS staff_username, 
               st.id AS student_id, st.username AS student_username
        FROM staff_student_relationship r
        JOIN users s ON r.staff_id = s.id
        JOIN users st ON r.student_id = st.id
    """)
    assignments = cursor.fetchall()

    cursor.close()

    return render_template('admin_dashboard.html', 
                           users=pending_users, 
                           staff_members=staff_members, 
                           students=students,
                           assignments=assignments)


@app.route('/admin/approve/<int:user_id>', methods=['POST'])
def approve_user(user_id):
    print("Approve user route hit!")

    role = request.form.get('role', 'student')  # By default, it's 'student'
    
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE users SET account_status = 'approved', role = %s WHERE id = %s", (role, user_id))
    mysql.connection.commit()
    cursor.close()
    
    flash('User approved successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/assign-student', methods=['POST'])
def assign_student_to_staff():
    staff_id = request.form.get('staff_id')
    student_id = request.form.get('student_id')
    
    cursor = mysql.connection.cursor()

    # Check if the relationship already exists
    cursor.execute("SELECT * FROM staff_student_relationship WHERE staff_id = %s AND student_id = %s", (staff_id, student_id))
    existing_relation = cursor.fetchone()

    if existing_relation:
        return redirect(url_for('admin_dashboard', message="This student is already assigned to the selected staff!"))

    try:
        # Insert the new relationship
        cursor.execute("INSERT INTO staff_student_relationship (staff_id, student_id) VALUES (%s, %s)", (staff_id, student_id))
        mysql.connection.commit()

        flash('Student successfully assigned to staff!', 'success')

    except Exception as e:
        print(e)
        flash('An error occurred while assigning the student.', 'danger')

    finally:
        cursor.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/remove-assignment', methods=['POST'])
def remove_assignment():
    staff_id = request.form.get('staff_id')
    student_id = request.form.get('student_id')
    print(f"Trying to remove assignment: staff_id={staff_id}, student_id={student_id}")  # Print for debugging

    cursor = mysql.connection.cursor()
    try:
        cursor.execute("DELETE FROM staff_student_relationship WHERE staff_id = %s AND student_id = %s", (staff_id, student_id))
        mysql.connection.commit()
        flash('Assignment removed successfully!', 'success')
    except Exception as e:
        print(e)
        flash('An error occurred while removing the assignment.', 'danger')
    finally:
        cursor.close()

    return redirect(url_for('admin_dashboard'))



@app.route('/api/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    try:
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT id, password, account_status FROM users WHERE username = %s", [username])
        user = cursor.fetchone()
        cursor.close()
        # Check if the account is approved
        if user[2] != 'approved':
            return "Your account is awaiting approval.", 401
        # Check password
        if user and check_password_hash(user[1], password):
            # Set user_id in session to mark the user as logged in
            session['user_id'] = user[0]
        
            # Create JWT token
            token = jwt.encode({
                'user_id': user[0],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, SECRET_KEY, algorithm="HS256")
        
            # Return the token (if you're using it elsewhere) and redirect to the main app page
            # Depending on your frontend logic, you might opt to just redirect without returning the token
            return redirect(url_for('index'))
    except TypeError:
        pass
    else:
        return jsonify({"error": "Invalid credentials"}), 401


@app.route('/api/tasks/<int:selected_user_id>', methods=['GET'])
def get_tasks_for_selected_user(selected_user_id):
    try:
        logged_in_user_id = session['user_id']
        
        # Ensure the selected user is either the logged-in user or a student assigned to the logged-in staff
        cursor = mysql.connection.cursor()
        cursor.execute("SELECT role FROM users WHERE id = %s", [logged_in_user_id])
        user_role = cursor.fetchone()[0]
        
        if user_role == 'student' and logged_in_user_id != selected_user_id:
            return jsonify({"error": "Unauthorized access"}), 403

        if user_role == 'staff':
            # Check if the selected user is a student assigned to the staff
            cursor.execute("""
                SELECT student_id FROM staff_student_relationship 
                WHERE staff_id = %s AND student_id = %s
            """, (logged_in_user_id, selected_user_id))
            assignment = cursor.fetchone()

            if not assignment and logged_in_user_id != selected_user_id:
                return jsonify({"error": "Unauthorized access"}), 403

        # Updated SQL query to fetch assigner's name
        cursor.execute("""
            SELECT tasks.id, tasks.text, tasks.dueDate, tasks.estimated_time, tasks.description, assigner.name as assigned_by_name 
            FROM tasks 
            LEFT JOIN users AS assigner ON tasks.assigned_by = assigner.id 
            WHERE tasks.user_id = %s
        """, [selected_user_id])

        tasks = cursor.fetchall()
        cursor.close()

        tasks_list = []
        for task in tasks:
            task_dict = {
                "id": task[0],
                "text": task[1],
                "dueDate": task[2].strftime('%Y-%m-%d %H:%M:%S'),
                "estimated_time": task[3],
                "description": task[4].replace('\n', '<br>'),
                "assigned_by": task[5]  # Add the assigner's name from the query
            }
            tasks_list.append(task_dict)

        return jsonify(tasks_list)

    except Exception as e:
        logging.error(f"An error occurred in get_tasks_for_selected_user: {e}")
        return jsonify({"error": "An internal error occurred"}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def edit_task(task_id):
    # Extract the updated due time from the request
    new_due_time = request.json.get('dueDate')
    
    # Update the task in the database
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE tasks SET dueDate = %s WHERE id = %s", (new_due_time, task_id))
    mysql.connection.commit()
    cursor.close()

    return jsonify({"message": "Task updated successfully!"})


@app.route('/api/tasks/<int:task_id>/edit-description', methods=['PUT'])
def edit_task_description(task_id):
    new_description = request.json.get('description')
    
    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE tasks SET description = %s WHERE id = %s", (new_description, task_id))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({"message": "Description updated successfully!"}), 200


if __name__ == '__main__':
    app.run(debug=True)

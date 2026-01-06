from django.shortcuts import redirect, render
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login
from user.models import Profile
from django.contrib.auth.decorators import login_required
from tasks.models import Task
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from wallets.models import Wallet
from django.contrib.auth.models import User
from tasks.models import Task as TaskModel
from projects.models import Project

def index(request):
    return render(request, 'pages/index.html')

def loginPage(request):
    return render(request, 'pages/auth/login.html')

def registerPage(request):
    return render(request, 'pages/auth/register.html')

def registerUser(request):
    errors = {}
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        dob = request.POST.get('dob')
        phone = request.POST.get('phone')
        address = request.POST.get('address')
        gender = request.POST.get('gender')
        image = request.FILES.get('image')
        
        if User.objects.filter(username=username).exists():
            errors ["username"]= 'Username already exists.'
        if User.objects.filter(email=email).exists():
             errors ["email"]= 'Email already exists'
             
        try:
            validate_password(password)
            if password != confirm_password:
                errors ["confirm_password"] = 'passwords do not match'
        except Exception as e:
            errors ["password"] = e.messages
            errors ["confirm_password"] = e.messages

            
        if len(phone)!=10:
             errors ["phone"] = 'phone number should be 10 digits'            
        if errors:
            return render(request, 'pages/auth/register.html', {'errors': errors})
        user = User.objects.create_user(username=username, email=email, password=password, first_name=first_name, last_name=last_name)
        profile = Profile(user=user, dob=dob, phone=phone, address=address, gender=gender, role="employee", image=image, is_approved=False)
        profile.save()
        wallet = Wallet.objects.create(user = user, balance = 0)
        wallet.save()
        messages.success(request, "User created successfully")
        user.save()
        return redirect('/login')
    
def loginUser(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user= User.objects.filter(username=username)
        if user:
            authenticated_user = authenticate(request, username=username, password=password)
            if authenticated_user:
                # block login if profile not approved
                try:
                    if not authenticated_user.profile.is_approved:
                        return render(request, 'pages/auth/login.html', {"errors":{"username":"Account not approved by admin yet."}})
                except Exception:
                    pass
                login(request, authenticated_user)
                messages.success(request, "User Logged in successfully")
                return redirect('/dashboard')
            else:
                return render(request, 'pages/auth/login.html',{"errors":{"password":"Invalid password"}})
        else:
            return render(request, 'pages/auth/login.html',{"errors":{"username":"Invalid Username"}})

@login_required(login_url='/login')
def dashboard(request):
    role = request.user.profile.role
    if role == 'employee':
        return redirect('/employee/dashboard')
    elif role == 'employer':
        return redirect('/employer/dashboard')
    elif role == 'admin':
        return redirect('/admin/')
    else:
        return redirect('/login')
    
@login_required(login_url='/login')    
def employerDashboard(request):
    if request.user.profile.role != "employer":
        return redirect('/employee/dashboard')
    
    # Get approved employees and employer's projects
    users = User.objects.filter(profile__role='employee', profile__is_approved=True)
    projects = Project.objects.filter(user=request.user)
    
    # Get task progress
    pendingTasks = Task.objects.filter(status='Pending', user=request.user)[:10]
    completedTasks = Task.objects.filter(status='Completed', user=request.user)[:10]
    inProgressTasks = Task.objects.filter(status='In Progress', user=request.user)[:10]
    
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        status = request.POST.get('status', 'Pending')
        priority = request.POST.get('priority', 'Low')
        deadline = request.POST.get('deadline')
        user_id = request.POST.get('user')
        project_id = request.POST.get('project')
        
        errors = {}
        if len(title) < 3:
            errors["title"] = "Title must be at least 3 characters long."
        if description and len(description) < 5:
            errors["description"] = "Description must be at least 5 characters long."
        if not user_id or not project_id:
            errors["assignment"] = "Please select an employee and a project."
        
        if errors:
            return render(request, 'pages/employer/dashboard.html', {
                'pendingTasks': pendingTasks,
                'completedTasks': completedTasks,
                'inProgressTasks': inProgressTasks,
                'users': users,
                'projects': projects,
                'errors': errors
            })
        
        try:
            assigned_user = User.objects.get(id=user_id, profile__role='employee', profile__is_approved=True)
            project = Project.objects.get(id=project_id, user=request.user)
            task = Task.objects.create(
                title=title,
                description=description,
                status=status,
                priority=priority,
                deadline=deadline,
                user=request.user,
                assigned_user=assigned_user,
                project=project
            )
            messages.success(request, "Task created and assigned successfully")
            return redirect('/employer/dashboard')
        except (User.DoesNotExist, Project.DoesNotExist):
            messages.error(request, "Invalid employee or project selected.")
            return redirect('/employer/dashboard')
    
    return render(request, 'pages/employer/dashboard.html', {
        'pendingTasks': pendingTasks,
        'completedTasks': completedTasks,
        'inProgressTasks': inProgressTasks,
        'users': users,
        'projects': projects
    })

@login_required(login_url='/login')
def employeeDashboard(request):
    role = request.user.profile.role
    if role == "employee":
        pendingTasks = Task.objects.filter(status = 'Pending', assigned_user = request.user)[ :10]
        completedTasks = Task.objects.filter(status = 'Completed', assigned_user = request.user)[ :10]
        inProgressTasks = Task.objects.filter(status = 'In Progress', assigned_user = request.user)[ :10]
        return render(request, 'pages/employee/dashboard.html', {'pendingTasks':pendingTasks, 'completedTasks':completedTasks, 'inProgressTasks':inProgressTasks})
    else:
        return redirect('/employer/dashboard')
    
@login_required(login_url='/login')
def tasks(request):
    role = request.user.profile.role
    if role == "employer":
        return redirect('/employer/tasks/')
    elif role == "employee":
        return redirect('/employee/tasks/')
    else:
        return redirect('/')

@login_required(login_url='/login')
def employerTasks(request):
    role = request.user.profile.role
    if role == "employer":
        lowTasks = Task.objects.filter(user = request.user, priority = "Low")
        mediumTasks = Task.objects.filter(user = request.user, priority = "Medium")
        highTasks = Task.objects.filter(user= request.user, priority = "High")
        return render(request, 'pages/employer/tasks/task_page.html', {'lowTasks': lowTasks, 'mediumTasks':mediumTasks, 'highTasks': highTasks})
    else:
        return redirect ('/employee/tasks')
    
@login_required(login_url='/login')
def employeeTasks(request):
    role = request.user.profile.role
    if role == "employee":
        lowTasks = Task.objects.filter(assigned_user = request.user, priority = "Low")
        mediumTasks = Task.objects.filter(assigned_user = request.user, priority = "Medium")
        highTasks = Task.objects.filter(assigned_user= request.user, priority = "High")
        return render(request, 'pages/employee/tasks/task_page.html', {'lowTasks': lowTasks, 'mediumTasks':mediumTasks, 'highTasks': highTasks})
    else:
        return redirect ('/employer/tasks')

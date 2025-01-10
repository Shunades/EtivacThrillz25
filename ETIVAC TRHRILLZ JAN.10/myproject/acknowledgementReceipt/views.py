from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from .models import CustomUser, RidesAttraction, TicketReservation, gate_adminaccount, RidesAttraction_Archive, TicketReservation_Archive, EAAdminAccount
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.utils import timezone  # Import timezone
from django.contrib.auth import logout as auth_logout
import random, logging
import qrcode
from io import BytesIO
import base64
from django.contrib.auth import authenticate, login
from django.conf import settings
from xhtml2pdf import pisa
from django.template.loader import render_to_string
import uuid
from django.utils.crypto import get_random_string
from django.contrib.auth.models import User  # Replace with your user model if different
from django.core.mail import send_mail  # Replace with your user model if different
from django.urls import reverse
from django.contrib.auth import get_user_model  # Import this to use the custom user model
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from .models import TicketReservation
from django.core.cache import cache  # Import the cache


# Temporary storage for OTPs (use a database for production)
OTP_STORAGE = {}

CustomUser = get_user_model()

otp_storage = {}

ADMIN_EMAILS = [
    'admin1@etivacthrillz.admin.com',
    'admin2@etivacthrillz.admin.com',
    'admin3@etivacthrillz.admin.com'
]

def forgot_password(request):
    """
    Handle the 'Forgot Password' request. 
    If the user is a gate admin or belongs to the updated admin list,
    show a popup. Otherwise, proceed with OTP.
    """
    if request.method == 'POST':
        email = request.POST.get('email').strip().lower()  # Normalize email

        # Check if the email is in the admin email list
        if email in ADMIN_EMAILS:
            messages.error(
                request,
                "This account is an admin account. Please contact the system administrator for assistance."
            )
            return redirect('forgot_password')

        # Check if the email belongs to a gate admin
        if email.endswith('@etivacthrillz.gateadmin.com'):
            try:
                if gate_adminaccount.objects.filter(email__iexact=email).exists():
                    messages.error(
                        request, 
                        "This account belongs to a domain admin. Please contact your domain administrator for assistance."
                    )
                    return redirect('forgot_password')
            except gate_adminaccount.DoesNotExist:
                pass

        # Proceed with OTP for other users
        try:
            user = CustomUser.objects.get(email__iexact=email)
        except CustomUser.DoesNotExist:
            messages.error(request, "No account found with that email.")
            return redirect('forgot_password')

        # Generate an OTP
        otp = get_random_string(6, allowed_chars='0123456789')  # Generate a 6-digit OTP
        cache.set(email, otp, timeout=300)  # Store OTP in cache for 5 minutes

        # Send the OTP to the user's email
        try:
            subject = "Your Password Reset OTP"
            message = f"""
            Hi {user.username},

            You requested to reset your password. Use the OTP below to reset your password:

            OTP: {otp}

            Note: This OTP is valid for only 5 minutes.

            If you didn't request this, please ignore this email.

            Best regards,
            The Etivac Thrillz Team
            """
            send_mail(subject, message, 'your_email@gmail.com', [email])
        except Exception as e:
            messages.error(request, "Failed to send email. Please try again later.")
            return redirect('forgot_password')

        messages.success(request, "An OTP has been sent to your email. Note: The OTP is valid for only 5 minutes.")
        request.session['reset_email'] = email  # Store email in session
        return redirect('verify_otp')

    return render(request, 'ForgotPassword.html')


def verify_otp(request):
    """
    Verify the OTP provided by the user and redirect to reset password page.
    """
    if request.method == 'POST':
        email = request.session.get('reset_email')  # Retrieve email from session
        otp = request.POST.get('otp')

        # Check if the OTP is valid
        if email in otp_storage and otp_storage[email] == otp:
            # Clear the OTP from storage (optional for security)
            otp_storage.pop(email, None)

            # Redirect to reset password page
            messages.success(request, "OTP verified. You can now reset your password.")
            return redirect('reset_password')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return redirect('verify_otp')

    return render(request, 'VerifyOTP.html')


def reset_password(request):
    """
    Allow the user to reset their password after verifying the OTP.
    """
    email = request.session.get('reset_email')  # Retrieve email from session

    if not email:
        messages.error(request, "Session expired. Please try again.")
        return redirect('forgot_password')

    if request.method == 'POST':
        new_password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect('reset_password')

        # Update the user's password
        try:
            user = CustomUser.objects.get(email=email)
            user.password = make_password(new_password)
            user.save()

            # Clear the session
            request.session.pop('reset_email', None)

            messages.success(request, "Your password has been successfully reset.")
            return redirect('signin')
        except CustomUser.DoesNotExist:
            messages.error(request, "An error occurred. Please try again.")
            return redirect('forgot_password')

    return render(request, 'ResetPassword.html')

def check_login(request):
    # Check if the user is logged in by verifying session keys
    if 'user_id' not in request.session and 'admin_email' not in request.session and 'gate_admin_id' not in request.session:
        messages.error(request, "You must be logged in to access this page.")
        return True
    return False

def index(request):
    return render(request, 'mainPage.html')

def ridesAtt(request):
    rides = RidesAttraction.objects.all()
    return render(request, 'rides.html', {'rides': rides})

def signin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Gate Admin Login
        if email.endswith('@etivacthrillz.gateadmin.com'):
            try:
                gate_admin = gate_adminaccount.objects.get(email=email)
                if check_password(password, gate_admin.password):
                    request.session['gate_admin_id'] = gate_admin.id
                    request.session['gate_admin_email'] = gate_admin.email
                    request.session['session_source'] = 'gateadmin_signin'
                    return redirect('gateadmin_bh')
                else:
                    messages.error(request, "Invalid email or password for gate admin.")
            except gate_adminaccount.DoesNotExist:
                messages.error(request, "Invalid email or password for gate admin.")
        
        # Admin Login (Check for EAAdminAccount)
        else:
            try:
                admin_account = EAAdminAccount.objects.get(email=email)
                if check_password(password, admin_account.password):
                    request.session['admin_email'] = admin_account.email
                    request.session['session_source'] = 'admin_signin'
                    return redirect('eaadmin_history')
                else:
                    messages.error(request, "Invalid email or password for admin.")
            except EAAdminAccount.DoesNotExist:
                # Regular Customer Login (Check for CustomUser)
                if email.endswith('@gmail.com'):
                    try:
                        user = CustomUser.objects.get(email=email)
                        if check_password(password, user.password):
                            request.session['user_id'] = user.id
                            request.session['user_email'] = user.email
                            request.session['session_source'] = 'signin'
                            return redirect('costumer_main')  # Redirect to customer main page
                        else:
                            messages.error(request, "Invalid email or password.")
                    except CustomUser.DoesNotExist:
                        messages.error(request, "Invalid email or password.")
    
    return render(request, 'SignIn.html')


# Temporary storage for email verification codes (use cache in production)
verification_codes = {}

def Signup(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        # Check if username or email already exists
        if CustomUser.objects.filter(username=username).exists():
            messages.error(request, "Username already exists.")
            return redirect('signup')
        if CustomUser.objects.filter(email=email).exists():
            messages.error(request, "Email already exists.")
            return redirect('signup')

        # Generate a verification code
        verification_code = get_random_string(6, allowed_chars='0123456789')  # 6-digit numeric code
        verification_codes[email] = verification_code

        # Send the verification code to the user's email
        subject = "Verify Your Email Address"
        message = f"""
        Hi there,

        Thank you for signing up with Etivac Thrillz! We're excited to have you on board.
        
        To complete your registration, please verify your email address by entering the code below:

        Verification Code: {verification_code}

        If you didn't sign up for an account, please ignore this email.

        Best regards,
        The Etivac Thrillz Team
        """
        send_mail(subject, message, 'your_email@gmail.com', [email])

        # Temporarily store user data in the session
        request.session['signup_data'] = {
            'username': username,
            'email': email,
            'password': make_password(password),  # Hash the password before storing
        }

        # Redirect to the email verification page
        messages.info(request, "A verification code has been sent to your email.")
        return redirect('verify_email')

    return render(request, 'SignUp.html')


def verify_email(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        code = request.POST.get('code')

        if email in verification_codes and verification_codes[email] == code:
            signup_data = request.session.get('signup_data')
            if signup_data and signup_data['email'] == email:
                CustomUser.objects.create(
                    username=signup_data['username'],
                    email=signup_data['email'],
                    password=signup_data['password'],
                )

                # Clean up session and verification data
                request.session.pop('signup_data', None)
                verification_codes.pop(email, None)

                # Send a success message
                messages.success(request, "Account created successfully! Please log in to your account.")
                return redirect('signin')
            else:
                messages.error(request, "Session expired. Please try signing up again.")
                return redirect('signup')
        else:
            messages.error(request, "Invalid verification code.")
            return redirect('verify_email')

    signup_data = request.session.get('signup_data', {})
    return render(request, 'VerifyEmail.html', {'email': signup_data.get('email', '')})

RESET_PASSWORD_TOKENS = {}



def user_logout(request):
    auth_logout(request)  # Logs out the user
    messages.success(request, "You have logged out successfully.", extra_tags='logout')  # Proper logout message
    return redirect('signin')  # Redirect to login page

def costumer_main(request):
    if check_login(request):
        return redirect('signin')
    return render(request, 'customerMain.html')

def submit_ticket(request):
    if check_login(request):
        return redirect('signin')
    return render(request, 'customerBuyticket.html')


def cost_rides(request):
    if check_login(request):
        return redirect('signin')
    
    costrides = RidesAttraction.objects.all()  # Fetches all attraction records
    return render(request, 'customerRidesattractions.html', {'costrides': costrides})

def cost_acc(request):   
    user_email = request.session.get('user_email')

    if user_email:
        user = CustomUser.objects.get(email=user_email)
        ticket_data = TicketReservation.objects.filter(customer_email=user_email)

        # Handle password change request
        if request.method == 'POST':
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')

            # Check if the current password matches the stored password
            if check_password(current_password, user.password):
                # Check if the new passwords match
                if new_password == confirm_password:
                    # Update the password and save the user
                    user.password = make_password(new_password)
                    user.save()
                    messages.success(request, "Password changed successfully.")
                else:
                    messages.error(request, "New passwords do not match.")
            else:
                messages.error(request, "Current password is incorrect.")
        
        # Check if the email ends with '@gmail.com'
        is_gmail = user_email.endswith('@gmail.com')

        context = {
            'ticket_reservations': ticket_data,
            'username': user.username,
            'email': user.email,
            'is_gmail': is_gmail,
        }

        return render(request, 'customerAccount.html', context)
    else:
        return redirect('signin')  # Redirect to login if user is not authenticated

def admin_acc(request):
    # Get the logged-in admin's email from the session
    admin_email = request.session.get('admin_email')

    if not admin_email:
        # Redirect if admin_email is not set (unauthorized access)
        messages.error(request, "You must be logged in to access this page.")
        return redirect('signin')  # Redirect to the login page

    try:
        # Retrieve the admin user from the database using the email
        admin_account = EAAdminAccount.objects.get(email=admin_email)

    except EAAdminAccount.DoesNotExist:
        # Handle the case where the admin account is not found
        messages.error(request, "Admin account not found.")
        return redirect('signin')

    # Handle password change request
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        # Verify current password
        if check_password(current_password, admin_account.password):
            if new_password == confirm_password:
                # Update and save the new password
                admin_account.password = make_password(new_password)
                admin_account.save()
                messages.success(request, "Password changed successfully.")
            else:
                messages.error(request, "New passwords do not match.")
        else:
            messages.error(request, "Current password is incorrect.")

    # Prepare the context for the template
    context = {
        'admin_email': admin_account.email,
    }
    return render(request, 'adminAccount.html', context)

def admin_history(request):
    if check_login(request):
        return redirect('signin')

    # Retrieve all ticket data
    ticket_data = TicketReservation.objects.all()

    # Filter by status if a filter is provided
    status_filter = request.GET.get('status')
    if status_filter:
        ticket_data = ticket_data.filter(status=status_filter.upper())

    # Handle sorting based on the selected criteria
    sort_criteria = request.GET.get('sort')
    if sort_criteria:
        if sort_criteria == 'name':
            ticket_data = ticket_data.order_by('customer_name')  # Sort by name alphabetically
        elif sort_criteria == 'date':
            ticket_data = ticket_data.order_by('date_of_purchase')  # Sort by date of purchase
        elif sort_criteria == 'status':
            # Custom ordering to sort by status (PENDING, PAID, DECLINED)
            status_order = {'PENDING': 1, 'PAID': 2, 'DECLINED': 3}
            ticket_data = sorted(ticket_data, key=lambda x: status_order.get(x.status, 0))

    # Handle POST requests for removing or updating ticket statuses
    if request.method == 'POST':
        selected_tickets = request.POST.getlist('ticket')  # Get selected ticket IDs

        # Check if a status update (PAID, DECLINED, or PENDING) is being requested
        if 'status' in request.POST:
            status = request.POST['status']
            if status in ['PAID', 'DECLINED', 'PENDING']:
                for ticket_id in selected_tickets:
                    try:
                        ticket = TicketReservation.objects.get(id=ticket_id)
                        ticket.status = status
                        ticket.save()  # Save the updated ticket
                    except TicketReservation.DoesNotExist:
                        print(f"Ticket with ID {ticket_id} does not exist.")  # Debugging log
                        continue

            # Return JSON response for successful status update
            return JsonResponse({'status': 'success', 'message': f'Tickets updated to {status} successfully'})

        # Check if tickets are to be removed
        if 'action' in request.POST and request.POST['action'] == 'remove':
            for ticket_id in selected_tickets:
                try:
                    remove_ticket = TicketReservation.objects.get(id=ticket_id)
                    # Archive the ticket before removing
                    TicketReservation_Archive.objects.create(
                        customer_name_archive=remove_ticket.customer_name,
                        customer_email_archive=remove_ticket.customer_email,
                        unlimited_quantity_archive=remove_ticket.unlimited_quantity,
                        limited_quantity_archive=remove_ticket.limited_quantity,
                        number_of_rides_archive=remove_ticket.number_of_rides,
                        receipt_of_payment_archive=remove_ticket.receipt_of_payment,
                        total_price_archive=remove_ticket.total_price,
                        ticket_date_availed=remove_ticket.ticket_date_availed,
                        date_of_purchase_archive=remove_ticket.date_of_purchase
                    )
                    remove_ticket.delete()  # Remove the ticket
                except TicketReservation.DoesNotExist:
                    print(f"Ticket with ID {ticket_id} does not exist.")  # Debugging log
                    continue

            # Return JSON response for successful removal
            return JsonResponse({'status': 'success', 'message': 'Selected tickets removed successfully'})

    # Render the template with the retrieved data
    return render(request, 'adminBookingHistory.html', {'ticket_reservations': ticket_data})

def generate_report(request):
    # Query all ticket reservations
    tickets = TicketReservation.objects.all()

    # Prepare the data to align with the front-end table
    report_data = []
    for ticket in tickets:
        ticket_data = {
            'Name': ticket.customer_name,
            'Email': ticket.customer_email,
            'Tickets_Types': f"{'Unlimited' if ticket.unlimited_quantity > 0 else ''}" +
                             (", Limited" if ticket.limited_quantity > 0 else ""),
            'Number_of_Rides': ticket.number_of_rides,
            'Date_Reservation': ticket.date_of_purchase.strftime('%Y-%m-%d %H:%M'),
            'Receipt_of_Payment': ticket.receipt_of_payment,
            'Total_Price': f"{ticket.total_price:.2f}"
        }
        report_data.append(ticket_data)

    # Render the report template
    html_content = render_to_string('report_template.html', {'report_data': report_data})

    # Create a PDF response
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="booking_history_report.pdf"'

    # Generate the PDF using xhtml2pdf
    pisa_status = pisa.CreatePDF(html_content, dest=response)

    # Handle PDF generation errors
    if pisa_status.err:
        return HttpResponse('Error generating PDF', status=400)

    return response

def eaadmin_create(request):
    if check_login(request):
        return redirect('signin')

    if request.method == 'POST':
        first_name = request.POST.get('firstName')
        last_name = request.POST.get('lastName')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirmPassword')

        # Validate form fields
        if not all([first_name, last_name, email, password, confirm_password]):
            messages.error(request, "All fields are required.")
            return render(request, 'adminCreateAcc.html', {'first_name': first_name, 'last_name': last_name, 'email': email})

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'adminCreateAcc.html', {'first_name': first_name, 'last_name': last_name, 'email': email})

        # Check if email already exists
        if gate_adminaccount.objects.filter(email=email).exists():
            messages.error(request, "Email already in use.")
            return render(request, 'adminCreateAcc.html', {'first_name': first_name, 'last_name': last_name, 'email': email})

        # Hash the password
        hashed_password = make_password(password)

        # Create and save the Gate Admin account
        gate_adminaccount.objects.create(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=hashed_password
        )

        messages.success(request, "Account created successfully!")
        return redirect('eaadmin_create')  # Change to a page you want to redirect to after successful account creation

    return render(request, 'adminCreateAcc.html')


def eaadmin_rides(request):
    if check_login(request):
        return redirect('signin')
    
    if request.method == 'POST':
        ride_id = request.POST.get('ride_id')
        description = request.POST.get('description')
        image = request.FILES.get('image')
        information = request.POST.get('info')
        category = request.POST.get('category')  # Category for the ride

        # Updating an existing ride
        if ride_id:  # Updating an existing ride
            try:
                attraction = RidesAttraction.objects.get(id=ride_id)
                
                if description:
                    attraction.description = description
                if image:
                    attraction.image = image
                if information:
                    attraction.information = information
                if category:  # Update the category if provided
                    attraction.category = category
                
                attraction.save()
                return JsonResponse({'status': 'success', 'message': 'Ride updated successfully!'})
            except RidesAttraction.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Ride not found'}, status=404)

        # Archiving a ride
        elif 'archive_ride_id' in request.POST:  # Archive an existing ride
            archive_ride_id = request.POST.get('archive_ride_id')
            try:
                attraction = RidesAttraction.objects.get(id=archive_ride_id)
                
                archived_attraction = RidesAttraction_Archive(
                    picture=attraction.image,
                    archived_description=attraction.description,
                    archived_information=attraction.information
                )
                archived_attraction.save()
                attraction.delete()
                return JsonResponse({'status': 'success', 'message': 'Ride archived and removed successfully'})
            except RidesAttraction.DoesNotExist:
                return JsonResponse({'status': 'error', 'message': 'Ride not found for archiving'}, status=404)

        # Adding a new ride
        if description and image and information and category:
            try:
                new_attraction = RidesAttraction(
                    description=description,
                    image=image,
                    information=information,
                    category=category  # Save the category
                )
                new_attraction.save()

                return JsonResponse({
                    'status': 'success',
                    'id': new_attraction.id,
                    'description': new_attraction.description,
                    'image_url': new_attraction.image.url,
                    'category': new_attraction.category,
                    'info': new_attraction.information,
                })
            except Exception as e:
                return JsonResponse({'status': 'error', 'message': f"Failed to add ride: {str(e)}"}, status=500)
        else:
            return JsonResponse({'status': 'error', 'message': "Please provide image, description, information, and category."}, status=400)

    # Display all rides (for GET request)
    attractions = RidesAttraction.objects.all()
    return render(request, 'adminRidesandAttractions.html', {'attractions': attractions})


def gateadmin_acc(request):
    # Retrieve the logged-in gate admin email from the session
    gateadmin_email = request.session.get('gate_admin_email')

    # Check if the email exists in the session
    if gateadmin_email:
        try:
            # Fetch the gate admin account using the email
            admin_account = gate_adminaccount.objects.get(email=gateadmin_email)

            # Handle password change request
            if request.method == 'POST':
                current_password = request.POST.get('current_password')
                new_password = request.POST.get('new_password')
                confirm_password = request.POST.get('confirm_password')

                # Check if the current password matches the stored password
                if check_password(current_password, admin_account.password):
                    # Check if the new passwords match
                    if new_password == confirm_password:
                        # Update the password and save the user
                        admin_account.password = make_password(new_password)
                        admin_account.save()
                        messages.success(request, "Password changed successfully.")
                    else:
                        messages.error(request, "New passwords do not match.")
                else:
                    messages.error(request, "Current password is incorrect.")
            
            # Context to pass to the template (only name and email)
            context = {
                'admin_first_name': admin_account.first_name,
                'admin_last_name': admin_account.last_name,
                'admin_email': admin_account.email,
            }

            return render(request, 'gateAdminAccount.html', context)

        except gate_adminaccount.DoesNotExist:
            # If the admin account is not found
            messages.error(request, "Admin account not found.")
            return redirect('signin')
    else:
        # If no admin email is found in the session, redirect to the login page with an error message
        messages.error(request, "You need to log in first.")
        return redirect('signin')

def gateadmin_bh(request):
    if check_login(request):
        return redirect('signin')

    # Retrieve all ticket data
    ticket_data = TicketReservation.objects.all()

    # Filter by status if a filter is provided
    status_filter = request.GET.get('status')
    if status_filter:
        ticket_data = ticket_data.filter(status=status_filter.upper())

    # Handle sorting based on the selected criteria
    sort_criteria = request.GET.get('sort')
    if sort_criteria:
        if sort_criteria == 'name':
            ticket_data = ticket_data.order_by('customer_name')  # Sort by name alphabetically
        elif sort_criteria == 'date':
            ticket_data = ticket_data.order_by('date_of_purchase')  # Sort by date of purchase
        elif sort_criteria == 'status':
            # Custom ordering to sort by status (PENDING, PAID, DECLINED)
            status_order = {'PENDING': 1, 'PAID': 2, 'DECLINED': 3}
            ticket_data = sorted(ticket_data, key=lambda x: status_order.get(x.status, 0))

    # Handle POST requests for removing or updating ticket statuses
    if request.method == 'POST':
        selected_tickets = request.POST.getlist('ticket')  # Get selected ticket IDs

        # Check if a status update (PAID, DECLINED, or PENDING) is being requested
        if 'status' in request.POST:
            status = request.POST['status']
            if status in ['PAID', 'DECLINED', 'PENDING']:
                for ticket_id in selected_tickets:
                    try:
                        ticket = TicketReservation.objects.get(id=ticket_id)
                        ticket.status = status
                        ticket.save()  # Save the updated ticket
                    except TicketReservation.DoesNotExist:
                        print(f"Ticket with ID {ticket_id} does not exist.")  # Debugging log
                        continue

            # Return JSON response for successful status update
            return JsonResponse({'status': 'success', 'message': f'Tickets updated to {status} successfully'})

        # Check if tickets are to be removed
        if 'action' in request.POST and request.POST['action'] == 'remove':
            for ticket_id in selected_tickets:
                try:
                    remove_ticket = TicketReservation.objects.get(id=ticket_id)
                    # Archive the ticket before removing
                    TicketReservation_Archive.objects.create(
                        customer_name_archive=remove_ticket.customer_name,
                        customer_email_archive=remove_ticket.customer_email,
                        unlimited_quantity_archive=remove_ticket.unlimited_quantity,
                        limited_quantity_archive=remove_ticket.limited_quantity,
                        number_of_rides_archive=remove_ticket.number_of_rides,
                        receipt_of_payment_archive=remove_ticket.receipt_of_payment,
                        total_price_archive=remove_ticket.total_price,
                        ticket_date_availed=remove_ticket.ticket_date_availed,
                        date_of_purchase_archive=remove_ticket.date_of_purchase
                    )
                    remove_ticket.delete()  # Remove the ticket
                except TicketReservation.DoesNotExist:
                    print(f"Ticket with ID {ticket_id} does not exist.")  # Debugging log
                    continue

            # Return JSON response for successful removal
            return JsonResponse({'status': 'success', 'message': 'Selected tickets removed successfully'})

    # Render the template with the retrieved data
    return render(request, 'gateAdminBH.html', {'ticket_reservations': ticket_data})

def gateadminticket(request):
    if check_login(request):  # Ensure this checks for authentication
        return redirect('signin')  # Redirect to the signin page if not authenticated

    if request.method == 'POST':
        # Get ticket details from form submission
        customer_name = request.POST.get('customer_name')
        customer_email = request.POST.get('customer_email')
        
        # Combine quantities for unlimited passes
        unlimited_passes = {
            'unlimited-pass': int(request.POST.get('unlimited-pass-quantity', 0)),
            'junior-pass': int(request.POST.get('junior-pass-quantity', 0)),
            'pwd-senior-pass': int(request.POST.get('pwd-senior-pass-quantity', 0))
        }
        unlimited_quantity = sum(unlimited_passes.values())

        # Get limited passes quantity
        limited_quantity = int(request.POST.get('rides-attractions-quantity', 0))

        # Calculate ticket details
        prices = {
            'unlimited-pass': 1000,
            'junior-pass': 700,
            'pwd-senior-pass': 700,
            'rides-attractions': 100,
        }

        tickets = {
            'unlimited-pass': {'quantity': unlimited_passes['unlimited-pass'], 'price': prices['unlimited-pass']},
            'junior-pass': {'quantity': unlimited_passes['junior-pass'], 'price': prices['junior-pass']},
            'pwd-senior-pass': {'quantity': unlimited_passes['pwd-senior-pass'], 'price': prices['pwd-senior-pass']},
            'rides-attractions': {'quantity': limited_quantity, 'price': prices['rides-attractions']}
        }

        # Calculate the total price
        total_price = sum(
            ticket['quantity'] * ticket['price'] for ticket in tickets.values() if ticket['quantity'] > 0
        )

        # Get the selected date for ticket availed
        ticket_date_availed = request.POST.get('ticket-date')
        if not ticket_date_availed:
            messages.error(request, "Please select a valid ticket availed date.")
            return redirect('gateadminticket')  # Redirect to the correct named URL for buying tickets

        # Generate a random number for the receipt of payment
        receipt_number = random.randint(100000, 999999)

        # Save the ticket reservation data to the database
        ticket_reservation = TicketReservation(
            customer_name=customer_name,
            customer_email=customer_email,
            unlimited_quantity=unlimited_quantity,
            limited_quantity=limited_quantity,
            number_of_rides=limited_quantity,  # Assuming each limited ticket is a single ride
            total_price=total_price,
            receipt_of_payment=receipt_number,
            date_of_purchase=timezone.now(),
            ticket_date_availed=ticket_date_availed  # Save the ticket_date_availed value
        )
        ticket_reservation.save()

        # Send a success message
        messages.success(request, "Ticket reservation created successfully!")

        # Define payment date and day pass date
        payment_date = timezone.now().strftime('%Y-%m-%d %H:%M:%S')
        day_pass_date = (timezone.now() + timezone.timedelta(days=7)).strftime('%Y-%m-%d')

        # Prepare ticket details for the invoice context
        availed_tickets = {
            ticket: {
                'quantity': details['quantity'],
                'price': details['price'],
                'total': details['quantity'] * details['price']
            }
            for ticket, details in tickets.items() if details['quantity'] > 0
        }

        # Pass data to both invoice views
        context = {
            'customer_name': customer_name,
            'customer_email': customer_email,
            'ticket_date': ticket_date_availed,  # Properly pass the date availed
            'availed_tickets': availed_tickets,
            'total_cost': total_price,
            'receipt_number': receipt_number,
            'payment_date': payment_date,
            'day_pass_date': day_pass_date,
        }

        # Check if it's a gate admin, redirect to gateAdminInvoice.html
        if customer_email.endswith('@etivacthrillz.gateadmin.com'):
            return render(request, 'gateAdminInvoice.html', context)

        # Otherwise, use the standard invoice.html
        return render(request, 'invoice.html', context)

    # Render the ticket purchase page
    return render(request, 'gateAdminbuyticket.html')



def invoice(request):
    if request.method == 'POST':
        # Collect customer data and ticket selections
        customer_name = request.POST.get('customer_name')
        customer_email = request.POST.get('customer_email')
        ticket_date = request.POST.get('ticket-date', '')  # Get the single date field

        # Tickets
        tickets = {
            'unlimited-pass': int(request.POST.get('unlimited-pass-quantity', 0)),
            'junior-pass': int(request.POST.get('junior-pass-quantity', 0)),
            'pwd-senior-pass': int(request.POST.get('pwd-senior-pass-quantity', 0)),
            'limited-pass': int(request.POST.get('rides-attractions-quantity', 0)),  # Renamed to 'limited-pass'
        }

        # Prices
        prices = {
            'unlimited-pass': 1000,
            'junior-pass': 700,
            'pwd-senior-pass': 700,
            'limited-pass': 100,  # Renamed to 'limited-pass'
        }

        # Combine unlimited passes into a single quantity
        unlimited_quantity = (
            tickets['unlimited-pass'] +
            tickets['junior-pass'] +
            tickets['pwd-senior-pass']
        )
        limited_quantity = tickets['limited-pass']  # Updated key to 'limited-pass'

        # Filter only tickets with quantity > 0
        availed_tickets = {
            ('Limited Pass' if ticket == 'limited-pass' else ticket): {  # Update display name
                'quantity': qty,
                'price': prices[ticket],
                'total': qty * prices[ticket]
            }
            for ticket, qty in tickets.items() if qty > 0
        }

        # Calculate total cost
        total_cost = sum(item['total'] for item in availed_tickets.values())

        # Render invoice template with all required data
        return render(request, 'invoice.html', {
            'customer_name': customer_name,
            'customer_email': customer_email,
            'ticket_date': ticket_date,  # Pass the selected ticket date
            'availed_tickets': availed_tickets,
            'unlimited_quantity': unlimited_quantity,
            'limited_quantity': limited_quantity,
            'total_cost': total_cost,
        })

    # Render the ticket purchase page if the request method is not POST
    return render(request, 'customerBuyTicket.html')



def payment_view(request):
    return render(request, 'proceed-to-payment.html')

def invoice2(request):
    if request.method == 'POST':
        # Collect gate admin data and ticket selections
        customer_name = request.POST.get('customer_name')
        customer_email = request.POST.get('customer_email')
        ticket_date = request.POST.get('ticket-date', '')  # Get the single date field

        # Validate the gate admin's email domain
        if not customer_email.endswith('@etivacthrillz.gateadmin.com'):
            messages.error(request, "Unauthorized access. Gate Admin email is required.")
            return redirect('signin')

        # Tickets
        tickets = {
            'unlimited-pass': int(request.POST.get('unlimited-pass-quantity', 0)),
            'junior-pass': int(request.POST.get('junior-pass-quantity', 0)),
            'pwd-senior-pass': int(request.POST.get('pwd-senior-pass-quantity', 0)),
            'limited-pass': int(request.POST.get('rides-attractions-quantity', 0)),  # Renamed to 'limited-pass'
        }

        # Prices
        prices = {
            'unlimited-pass': 1000,
            'junior-pass': 700,
            'pwd-senior-pass': 700,
            'limited-pass': 100,  # Renamed to 'limited-pass'
        }

        # Combine unlimited passes into a single quantity
        unlimited_quantity = (
            tickets['unlimited-pass'] +
            tickets['junior-pass'] +
            tickets['pwd-senior-pass']
        )
        limited_quantity = tickets['limited-pass']  # Updated key to 'limited-pass'

        # Filter only tickets with quantity > 0
        availed_tickets = {
            ('Limited Pass' if ticket == 'limited-pass' else ticket): {  # Update display name
                'quantity': qty,
                'price': prices[ticket],
                'total': qty * prices[ticket]
            }
            for ticket, qty in tickets.items() if qty > 0
        }

        # Calculate total cost
        total_cost = sum(item['total'] for item in availed_tickets.values())

        # Render gate admin invoice template with all required data
        return render(request, 'gateAdminInvoice.html', {
            'customer_name': customer_name,
            'customer_email': customer_email,
            'ticket_date': ticket_date,  # Pass the selected ticket date
            'availed_tickets': availed_tickets,
            'unlimited_quantity': unlimited_quantity,
            'limited_quantity': limited_quantity,
            'total_cost': total_cost,
        })

    # Render the gate admin ticket purchase page if the request method is not POST
    return render(request, 'gateAdminBuyTicket.html')

def payment_view2(request):
    return render(request ,'proceed-to-payment2.html')
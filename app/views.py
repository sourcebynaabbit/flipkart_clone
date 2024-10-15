from django.shortcuts import render, redirect, get_object_or_404
from .models import Product, Cart, Orders, Address, Payment
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.generic.edit import CreateView, UpdateView, DeleteView
from django.views.generic.list import ListView

# Create your views here.


def index(req):
    allproducts = Product.objects.all()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


# class ProductRegister(CreateView):
#     model = Product
#     fields = "__all__"
#     success_url = "/ProductList"


class ProductRegister(CreateView):
    model = Product
    fields = "__all__"  # Includes the 'user' field by default
    success_url = "/ProductList"

    def get_form(self, form_class=None):
        form = super().get_form(form_class)
        # Customize how the 'user' field is displayed in the dropdown
        form.fields["userid"].label_from_instance = (
            lambda obj: f"{obj.username}"
        )  # Display the username
        return form


# class ProductList(ListView):
#     model = Product
#     queryset = Product.objects.filter(userid=id)


def ProductList(req):
    if req.user.is_authenticated:
        user = req.user
        object_list = Product.objects.filter(userid=user)
        context = {"object_list": object_list, "username": user}
        return render(req, "app/product_list.html", context)
    else:
        user = None
        return redirect("/signin")


class ProductUpdate(UpdateView):
    model = Product
    template_name_suffix = "_update_form"
    fields = "__all__"
    success_url = "/ProductList"


class ProductDelete(DeleteView):
    model = Product
    success_url = "/ProductList"


from django.core.exceptions import ValidationError


def validate_password(password):
    # Check minimum length
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters long.")

    # Check maximum length
    if len(password) > 128:
        raise ValidationError("Password cannot exceed 128 characters.")

    # Initialize flags for character checks
    has_upper = False
    has_lower = False
    has_digit = False
    has_special = False
    special_characters = "@$!%*?&"

    # Check for character variety
    for char in password:
        if char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char.isdigit():
            has_digit = True
        elif char in special_characters:
            has_special = True

    if not has_upper:
        raise ValidationError("Password must contain at least one uppercase letter.")
    if not has_lower:
        raise ValidationError("Password must contain at least one lowercase letter.")
    if not has_digit:
        raise ValidationError("Password must contain at least one digit.")
    if not has_special:
        raise ValidationError(
            "Password must contain at least one special character (e.g., @$!%*?&)."
        )

    # Check against common passwords
    common_passwords = [
        "password",
        "123456",
        "qwerty",
        "abc123",
    ]  # Add more common passwords
    if password in common_passwords:
        raise ValidationError("This password is too common. Please choose another one.")


def signup(req):
    if req.method == "POST":
        uname = req.POST["uname"]
        email = req.POST["email"]
        upass = req.POST["upass"]
        ucpass = req.POST["ucpass"]
        context = {}
        try:
            validate_password(upass)
        except ValidationError as e:
            context["errmsg"] = str(e)
            return render(req, "signup.html", context)

        if uname == "" or email == "" or upass == "" or ucpass == "":
            context["errmsg"] = "Field can't be empty"
            return render(req, "signup.html", context)
        elif upass != ucpass:
            context["errmsg"] = "Password and confirm password doesn't match"
            return render(req, "signup.html", context)
        elif uname.isdigit():
            context["errmsg"] = "Username cannot consist solely of numbers."
            return render(req, "signup.html", context)
        else:
            try:
                userdata = User.objects.create(
                    username=uname, email=email, password=upass
                )
                userdata.set_password(upass)
                userdata.save()
                return redirect("/signin")
            except:
                context["errmsg"] = "User Already exists"
                return render(req, "signup.html", context)
    else:
        context = {}
        context["errmsg"] = ""
        return render(req, "signup.html", context)


def signin(req):
    if req.method == "POST":
        email = req.POST["email"]
        upass = req.POST["upass"]
        context = {}
        if email == "" or upass == "":
            context["errmsg"] = "Field can't be empty"
            return render(req, "signin.html", context)
        else:
            try:
                user = User.objects.get(email=email)  # Retrieve user by email
                userdata = authenticate(username=user.username, password=upass)
                print(userdata)
                if userdata is not None:
                    login(req, userdata)
                    return redirect("/")
                else:
                    context["errmsg"] = "Invalid username and password"
                    return render(req, "signin.html", context)
            except:
                context["errmsg"] = "User doesn't exist"
                return render(req, "signin.html", context)
    else:
        return render(req, "signin.html")


def userlogout(req):
    logout(req)
    return redirect("/")


from django.contrib import messages


def request_password_reset(req):
    if req.method == "POST":
        email = req.POST.get("email")
        context = {}

        # Check if the email exists
        try:
            user = User.objects.get(email=email)
            # Redirect to the password reset page
            return redirect("reset_password", username=user.username)
        except User.DoesNotExist:
            context["errmsg"] = "No account found with that email."
            return render(req, "request_password_reset.html", context)

    return render(req, "request_password_reset.html")


def reset_password(req, username):
    try:
        user = User.objects.get(username=username)

        if req.method == "POST":
            new_password = req.POST.get("new_password")
            try:
                validate_password(new_password)
                user.set_password(new_password)  # Hash the password
                user.save()
                messages.success(req, "Your password has been reset successfully.")
                return redirect(
                    "signin"
                )  # Redirect to the signin page after successful reset

            except ValidationError as e:
                messages.error(req, str(e))  # Show the validation error message
                return render(
                    req, "reset_password.html", {"username": username}
                )  # Stay on the same page

        return render(req, "reset_password.html", {"username": username})

    except User.DoesNotExist:
        messages.error(req, "User not found.")
        return redirect("request_password_reset")


def fashionlist(req):
    allproducts = Product.productmanager.fashion_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def shoeslist(req):
    allproducts = Product.productmanager.shoes_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def mobilelist(req):
    allproducts = Product.productmanager.mobile_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def electronicslist(req):
    allproducts = Product.productmanager.electronics_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def clothlist(req):
    allproducts = Product.productmanager.cloth_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def grocerylist(req):
    allproducts = Product.productmanager.grocery_list()
    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


from django.db.models import Q


def searchproduct(req):
    query = req.GET.get("q")
    errmsg = ""
    if query:
        allproducts = Product.objects.filter(
            Q(productname__icontains=query)
            | Q(category__icontains=query)
            | Q(description__icontains=query)
        )
        if len(allproducts) == 0:
            errmsg = "No result found!!"

    else:
        allproducts = Product.objects.all()

    context = {"allproducts": allproducts, "errmsg": errmsg}
    return render(req, "index.html", context)


def showpricerange(req):
    if req.method == "GET":
        return render(req, "index.html")
    else:
        r1 = req.POST["min"]
        r2 = req.POST.get("max")
        print(r1, r2)
        if r1 is not None and r2 is not None and r1.isdigit() and r2.isdigit():
            allproducts = Product.objects.filter(price__range=(r1, r2))
            print(allproducts)
            context = {"allproducts": allproducts}
            return render(req, "index.html", context)
        else:
            allproducts = Product.objects.all()
            context = {"allproducts": allproducts}
            return render(req, "index.html", context)


def sortingbyprice(req):
    sortoption = req.GET.get("sort")
    if sortoption == "low_to_high":
        allproducts = Product.objects.order_by("price")  # asc order
    elif sortoption == "high_to_low":
        allproducts = Product.objects.order_by("-price")  # desc order
    else:
        allproducts = Product.objects.all()

    context = {"allproducts": allproducts}
    return render(req, "index.html", context)


def showcarts(req):
    user = req.user
    allcarts = Cart.objects.filter(userid=user.id)
    totalamount = 0

    for x in allcarts:
        totalamount += x.productid.price * x.qty

    totalitems = len(allcarts)

    if req.user.is_authenticated:
        context = {
            "allcarts": allcarts,
            "username": user,
            "totalamount": totalamount,
            "totalitems": totalitems,
        }
    else:
        context = {
            "allcarts": allcarts,
            "totalamount": totalamount,
            "totalitems": totalitems,
        }

    return render(req, "showcarts.html", context)


def addtocart(req, productid):
    if req.user.is_authenticated:
        user = req.user
    else:
        user = None

    allproducts = get_object_or_404(Product, productid=productid)  # primary key
    cartitem, created = Cart.objects.get_or_create(
        productid=allproducts, userid=user
    )  # foreignkey
    if not created:
        cartitem.qty += 1
    else:
        cartitem.qty = 1

    cartitem.save()
    return redirect("/showcarts")


def removecart(req, productid):
    user = req.user
    cartitems = Cart.objects.get(productid=productid, userid=user.id)
    cartitems.delete()
    return redirect("/showcarts")


def updateqty(req, qv, productid):
    allcarts = Cart.objects.filter(productid=productid)
    if qv == 1:
        total = allcarts[0].qty + 1
        allcarts.update(qty=total)
    else:
        if allcarts[0].qty > 1:
            total = allcarts[0].qty - 1
            allcarts.update(qty=total)
        else:
            allcarts = Cart.objects.filter(productid=productid)
            allcarts.delete()

    return redirect("/showcarts")


from .forms import AddressForm


def addaddress(req):
    if req.user.is_authenticated:
        if req.method == "POST":
            form = AddressForm(req.POST)
            if form.is_valid():
                address = form.save(commit=False)
                address.userid = req.user
                address.save()
                return redirect("/showaddress")
        else:
            form = AddressForm()

        context = {"form": form}
        return render(req, "addaddress.html", context)
    else:
        return redirect("/signin")


def showaddress(req):
    if req.user.is_authenticated:
        addresses = Address.objects.filter(userid=req.user)
        if req.method == "POST":
            return redirect("/make_payment")

        context = {"addresses": addresses}
        return render(req, "showaddress.html", context)
    else:
        return redirect("/signin")


def about(req):
    return render(req, "about.html")


def contact(req):
    return render(req, "contact.html")


import razorpay
import random
from django.conf import settings
from django.core.mail import send_mail


def make_payment(req):
    if req.user.is_authenticated:
        cart_items = Cart.objects.filter(userid=req.user.id)
        total_amount = sum(item.productid.price * item.qty for item in cart_items)
        user = req.user
        client = razorpay.Client(
            auth=("rzp_test_wH0ggQnd7iT3nB", "eZseshY3oSsz2fcHZkTiSlCm")
        )
        try:
            data = {
                "amount": int(total_amount * 100),
                "currency": "INR",
                "receipt": str(random.randrange(1000, 90000)),
            }
            payment = client.order.create(data=data)

            for item in cart_items:
                order_id = random.randrange(1000, 90000)
                orderdata = Orders.objects.create(
                    orderid=order_id,
                    productid=item.productid,
                    userid=user,
                    qty=item.qty,
                )

                orderdata.save()
                Payment.objects.create(
                    receiptid=order_id,
                    orderid=orderdata,
                    userid=user,
                    productid=item.productid,
                    totalprice=item.qty * item.productid.price,
                )
            cart_items.delete()

            # subject = f"FlipKart Payment Status for your Order={order_id}"
            # msg = f"Hi {user}, Thank you for using our service\nTotal Amount Paid=Rs. {total_amount}"
            # emailfrom = settings.EMAIL_HOST_USER
            # receiver = [user, user.email]
            # send_mail(subject, msg, emailfrom, receiver)

            context = {"data": payment, "amount": total_amount}
            return render(req, "make_payment.html", context)
        except ValidationError as e:
            context = {}
            context["errmsg"] = (
                "An error occurred while creating payment order. Please try again"
            )
            print(e)
            return render(req, "make_payment.html", context)
    else:
        return redirect("/signin")


def showorders(req):
    if req.user.is_authenticated:
        userorders = Orders.objects.filter(userid=req.user).select_related("productid")
        return render(req, "showorders.html", {"orders": userorders})
    else:
        return redirect("/signin")

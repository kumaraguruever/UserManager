using CoreUserManagementDemo.Models;
using CoreUserManagementDemo.Models.Manage;
using CoreUserManagementDemo.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

[Authorize]
[Route("[controller]/[action]")]
public class ManageController : Controller
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IEmailSender _emailSender;

    private readonly ISmsSender _smsSender;
    private readonly ILogger _logger;
    private readonly UrlEncoder _urlEncoder;

    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";
    private const string RecoveryCodesKey = nameof(RecoveryCodesKey);

    public ManageController(
      UserManager<ApplicationUser> userManager,
      SignInManager<ApplicationUser> signInManager,
      IEmailSender emailSender,
      ISmsSender smsSender,
      ILogger<ManageController> logger,
      UrlEncoder urlEncoder)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _smsSender = smsSender;
        _emailSender = emailSender;
        _logger = logger;
        _urlEncoder = urlEncoder;
    }

    [TempData]
    public string StatusMessage { get; set; }

    [HttpGet]
    public async Task<IActionResult> Index()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var model = new IndexViewModel
        {
            Username = user.UserName,
            Email = user.Email,
            PhoneNumber = user.PhoneNumber,
            IsEmailConfirmed = user.EmailConfirmed,
            StatusMessage = StatusMessage
        };

        return View(model);
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> Index(IndexViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var email = user.Email;
        if (model.Email != email)
        {
            var setEmailResult = await _userManager.SetEmailAsync(user, model.Email);
            if (!setEmailResult.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred setting email for user with ID '{user.Id}'.");
            }
        }

        var phoneNumber = user.PhoneNumber;
        if (model.PhoneNumber != phoneNumber)
        {
            var setPhoneResult = await _userManager.SetPhoneNumberAsync(user, model.PhoneNumber);
            if (!setPhoneResult.Succeeded)
            {
                throw new ApplicationException($"Unexpected error occurred setting phone number for user with ID '{user.Id}'.");
            }
        }

        StatusMessage = "Your profile has been updated";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendVerificationEmail(IndexViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }

        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }

        var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
      //  var callbackUrl = Url.Ema(user.Id, code, Request.Scheme);
        var email = user.Email;
        await _emailSender.SendEmailAsync(email, "Email Confirmation", $"{user.UserName} is registered.");

        StatusMessage = "Verification email sent. Please check your email.";
        return RedirectToAction(nameof(Index));
    }

    [HttpPost]
    [ValidateAntiForgeryToken]
    public async Task<IActionResult> SendSMSVerification(IndexViewModel model)
    {
        if (!ModelState.IsValid)
        {
            return View(model);
        }
        var user = await _userManager.GetUserAsync(User);
        if (user == null)
        {
            throw new ApplicationException($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");
        }
        var phoneNumber = model.PhoneNumber;
        await _smsSender.SendSmsAsync(phoneNumber, "Your registration is succesful");

        StatusMessage = "Verification email sent. Please check your email.";
        return RedirectToAction(nameof(Index));
    }
    }
﻿

#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using PizzeriaImpulsMVC.Domain.Models;
using PizzeriaImpulsMVC.Domain.Interfaces;

namespace PizzeriaImpulsMVC.Web.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<UserAccount> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly IUserManagmentRepository _userManagmentRepository;

        public LoginModel(SignInManager<UserAccount> signInManager, 
                        ILogger<LoginModel> logger, 
                        IUserManagmentRepository userManagmentRepository)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManagmentRepository = userManagmentRepository;
        }

        
        
        
        
        [BindProperty]
        public InputModel Input { get; set; }

        
        
        
        
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        
        
        
        
        public string ReturnUrl { get; set; }

        
        
        
        
        [TempData]
        public string ErrorMessage { get; set; }

        
        
        
        
        public class InputModel
        {
            
            
            
            
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            
            
            
            
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            
            
            
            
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            bool isActive = _userManagmentRepository.IsUserActive(Input.Email);
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!isActive)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            if (ModelState.IsValid)
            {
                
                
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {  
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }           
            
            

            
            return Page();
        }
    }
}

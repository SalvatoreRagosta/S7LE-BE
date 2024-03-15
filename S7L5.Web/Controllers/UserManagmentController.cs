using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.UserManagment;

namespace PizzeriaImpulsMVC.Web.Controllers
{
    public class UserManagmentController : Controller
    {
        private readonly IUserManagmentService _userManagmentService;

        public UserManagmentController(IUserManagmentService userManagmentService)
        {
            _userManagmentService = userManagmentService;
        }

        [HttpGet]
        [Authorize(Roles = "Admin, Manager")]
        public IActionResult Index()
        {
            var users = _userManagmentService.GetAllUsersForList();

            return View(users);
        }

        [HttpGet]
        [Authorize(Roles = "Admin, Manager")]
        public IActionResult GetUserDetails(string userId)
        {
            var user = _userManagmentService.GetUserDetails(userId);

            return View(user);
        }


        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult DeleteUser(string userId)
        {
            _userManagmentService.DeleteUser(userId);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult RestoreUser(string userId)
        {
            _userManagmentService.RestoreUser(userId);

            return RedirectToAction("Index");
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult GetRoles()
        {
            var roles =_userManagmentService.GetRoles();

            return View(roles);
        }

        [HttpGet]
        [Route("rolesManagment/add")]
        [Authorize(Roles = "Admin")]
        public IActionResult AddRole()
        {
            return View(new NewRoleVm());
        }

        [HttpPost]
        [Route("rolesManagment/add")]
        [Authorize(Roles = "Admin")]
        public IActionResult AddRole(NewRoleVm newRoleVm)
        {
            _userManagmentService.AddRole(newRoleVm);

            return RedirectToAction("GetRoles");
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult ManageUserRoles(string userId) 
        {
            var rolesView = _userManagmentService.GenerateRolesView(userId);

            return View(rolesView);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        public IActionResult ManageUserRoles(string userId, ListRolesForListVm userRolesVm)
        {
            var userRoles = userRolesVm.Roles.Where(u => u.IsChecked == true).ToList();
            _userManagmentService.UpdateUserRoles(userId, userRoles);

            return RedirectToAction("Index");
        }
    }
}

using PizzeriaImpulsMVC.Application.ViewModels.UserManagment;

namespace PizzeriaImpulsMVC.Application.Interfaces
{
    public interface IUserManagmentService
    {
        void DeleteUser(string userId);
        void RestoreUser(string userId);
        ListUserForListVm GetAllUsersForList();
        UserForListVm GetUserDetails(string userId);
        UserForListVm GetUserByUserName(string userName);
        ListRolesForListVm GetRoles();
        void AddRole(NewRoleVm newRoleVm);
        ListUserRolesVm GetUserRoles(string userId);
        ListRolesForListVm GenerateRolesView(string userId);
        void UpdateUserRoles(string userId, List<RolesForListVm> userRolesVm);
    }
}

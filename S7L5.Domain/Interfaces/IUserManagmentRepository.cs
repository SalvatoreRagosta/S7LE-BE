using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IUserManagmentRepository
    {
       IQueryable<UserAccount> GetAllUsers();
       bool IsUserActive(string userEmail);
       UserAccount GetUserById(string userId);
       UserAccount GetUserByUserName(string userName);
       void DeleteUser(string userId);
       void RestoreUser(string userId);
       DbSet<IdentityRole> GetRoles();
       void AddRole(IdentityRole identityRole);
       IQueryable<IdentityUserRole<string>> GetUserRoles(string userId);
       void UpdateUserRoles(string userId, List<IdentityUserRole<string>> userRolesList);

    }
}

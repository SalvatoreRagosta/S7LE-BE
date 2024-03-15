using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    public class UserManagmentRepository : IUserManagmentRepository
    {
        private readonly Context _context;

        public UserManagmentRepository(Context context)
        {
            _context = context;
        }

        public IQueryable<UserAccount> GetAllUsers()
        {
            var users = _context.Users
                .Include(u => u.UserAddress)
                .OrderBy(e => e.Email)
                .OrderByDescending(a => a.IsActive);

            return users;
        }

        public bool IsUserActive(string userEmail)
        {
            var user = _context.Users.FirstOrDefault(u => u.Email == userEmail);

            if(user == null || user.IsActive == false )
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        public UserAccount GetUserById(string userId)
        {
            var user = _context.Users
                .Include(u => u.UserAddress)
                .FirstOrDefault(us => us.Id == userId);
            
            return user;
        }

        public UserAccount GetUserByUserName(string userName)
        {
            var user = _context.Users
                .Include(u => u.UserAddress)
                .FirstOrDefault(us => us.UserName == userName);

            return user;
        }

        public void DeleteUser(string userId)
        {
            var user = _context.Users.FirstOrDefault(u => u.Id == userId);

            user.IsActive = false;

            _context.Users.Update(user);
            _context.SaveChanges();
        }

        public void RestoreUser(string userId)
        {
            var user = _context.Users.FirstOrDefault(u => u.Id == userId);

            user.IsActive = true;

            _context.Users.Update(user);
            _context.SaveChanges();
        }

        public DbSet<IdentityRole> GetRoles()
        {
            var roles = _context.Roles;

            return roles;
        }

        public void AddRole(IdentityRole identityRole)
        {
            _context.Roles.Add(identityRole);
            _context.SaveChanges();
        }

        public IQueryable<IdentityUserRole<string>> GetUserRoles(string userId)
        {
            var userRoles = _context.UserRoles.Where(u => u.UserId == userId);

            return userRoles;
        }

        public void UpdateUserRoles(string userId, List<IdentityUserRole<string>> userRolesList)
        {
            var userRoles = _context.UserRoles.Where(u => u.UserId == userId);
           
            _context.UserRoles.RemoveRange(userRoles);
            _context.AddRange(userRolesList);
            _context.SaveChanges();
        }
    }
}

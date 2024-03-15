using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.UserManagment
{
    public class UserForListVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.UserAccount>
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public bool IsActive { get; set; }
        public string DateOfBirth { get; set; }
        public DateTime RegistrationDate { get; set; }
        public string Country { get; set; }
        public string City { get; set; }
        public string Street { get; set; }
        public int HomeNumber { get; set; }
        public int ApartmentNumber { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<PizzeriaImpulsMVC.Domain.Models.UserAccount, UserForListVm>();

        }
    }
}

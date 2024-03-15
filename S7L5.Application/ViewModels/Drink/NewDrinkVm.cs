using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.Drink
{
    public class NewDrinkVm :IMapFrom<PizzeriaImpulsMVC.Domain.Models.Drink>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public decimal Size { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<NewDrinkVm, PizzeriaImpulsMVC.Domain.Models.Drink>()
                .ReverseMap();
        }
    }
}

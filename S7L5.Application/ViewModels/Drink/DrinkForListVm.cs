using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.Drink
{
    public class DrinkForListVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.Drink>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public decimal Size { get; set; }
        public string? ImgPath { get; set; }


        public void Mapping(Profile profile)
        {
            profile.CreateMap<PizzeriaImpulsMVC.Domain.Models.Drink, DrinkForListVm>()
                .ReverseMap();
            
        }
    }
}

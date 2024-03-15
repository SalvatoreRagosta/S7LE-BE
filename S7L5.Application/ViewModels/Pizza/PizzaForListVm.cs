using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;
using PizzeriaImpulsMVC.Application.ViewModels.Component;

namespace PizzeriaImpulsMVC.Application.ViewModels.Pizza
{
    public class PizzaForListVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.Pizza>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public bool IsMeat { get; set; }
        public string? ImgPath { get; set; }

        public ICollection<ComponentForListVm> Components { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<PizzeriaImpulsMVC.Domain.Models.Pizza, PizzaForListVm>();
        }
    }
}

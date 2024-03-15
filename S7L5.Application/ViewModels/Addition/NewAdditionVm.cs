using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.Addition
{
    public class NewAdditionVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.Addition>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<NewAdditionVm, PizzeriaImpulsMVC.Domain.Models.Addition>()
                .ReverseMap();
        }
    }
}

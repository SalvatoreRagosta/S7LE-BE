using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.Component
{
    public class ComponentForListVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.Component>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public bool IsMeat { get; set; }
        public bool IsChecked { get; set; }
        public string? ImgPath { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<PizzeriaImpulsMVC.Domain.Models.Component, ComponentForListVm>()
                .ForMember(x => x.IsChecked, opt => opt.Ignore())
                .ReverseMap();
        }
    }
}

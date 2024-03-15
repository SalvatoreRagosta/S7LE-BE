using AutoMapper;
using PizzeriaImpulsMVC.Application.Mapping;

namespace PizzeriaImpulsMVC.Application.ViewModels.Addition
{
    public class AdditionForListVm : IMapFrom<PizzeriaImpulsMVC.Domain.Models.Addition>
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public int Price { get; set; }
        public string? ImgPath { get; set; }

        public void Mapping(Profile profile)
        {
            profile.CreateMap<PizzeriaImpulsMVC.Domain.Models.Addition, AdditionForListVm>();
        }
    }




}

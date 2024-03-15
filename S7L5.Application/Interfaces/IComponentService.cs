using PizzeriaImpulsMVC.Application.ViewModels.Component;

namespace PizzeriaImpulsMVC.Application.Interfaces
{
    public interface IComponentService
    {
        ListComponentForListVm GetAllComponentsForList(int pageSize, int pageNumber, string filterString);
        int AddNewComponent(NewComponentVm newComponentVm);
        void DeleteComponent(int componentId);
        List<ComponentForListVm> GetAllComponents();
        NewComponentVm GetComponentForEdit(int componentId);
        void EditComponent(NewComponentVm editComponentVm);
        ComponentForListVm GetComponentDetails(int componentId);

    }
}

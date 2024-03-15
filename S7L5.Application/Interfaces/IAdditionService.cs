using PizzeriaImpulsMVC.Application.ViewModels.Addition;

namespace PizzeriaImpulsMVC.Application.Interfaces
{
    public interface IAdditionService
    {
        ListAdditionForListVm GetAllAdditionsForList(int pageSize, int pageNumber, string filterString);
        int AddNewAddition(NewAdditionVm newAdditionVm);
        void DeleteAddition(int additionId);
        NewAdditionVm GetAdditionForEdit(int additionId);
        void EditAddition(NewAdditionVm additionForEdit);
        AdditionForListVm GetAdditionDetails(int additionId);
    }
}

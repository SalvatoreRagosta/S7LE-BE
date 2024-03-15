using PizzeriaImpulsMVC.Application.ViewModels.Component;
using PizzeriaImpulsMVC.Application.ViewModels.Pizza;

namespace PizzeriaImpulsMVC.Application.Interfaces
{
    public interface IPizzaService
    {
        int AddPizza(NewPizzaVm newPizzaVm, int pizzaId);
        List<ComponentForListVm> GetCheckedComponents(NewPizzaVm newPizzaVm);
        ListPizzaForListVm GetAllPizzasForList(int pageSize, int pageNumber, string filterString);
        List<PizzaForListVm> GetAllPizzas(string filterString);
        void DeletePizza(int pizzaId);
        NewPizzaVm GetPizzaForEdit(int pizzaId);
        PizzaForListVm GetPizzaDetails(int pizzaId);
        void EditPizza(NewPizzaVm newPizzaVm, int pizzaId);
        List<ComponentForListVm> UpdateIsCheckStatus(NewPizzaVm pizza, List<ComponentForListVm> components);
    }
}

using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Domain.Interfaces
{
    public interface IDrinkRepository
    {
        int AddDrink(Drink drink);
        void DeleteDrink(int drinkId);
        IQueryable<Drink> GetAllDrinks();
        Drink GetDrink(int drinkId);
        void EditDrink(Drink editedDrink);
        Drink GetDrinkById(int drinkId);
    }
}

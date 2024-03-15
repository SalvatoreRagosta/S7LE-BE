using Microsoft.EntityFrameworkCore;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PizzeriaImpulsMVC.Infrastructure.Repositories
{
    public class DrinkRepository : IDrinkRepository
    {
        private readonly Context _context;

        public DrinkRepository(Context context)
        {
            _context = context;
        }

        public int AddDrink(Drink drink)
        { 
            _context.Drinks.Add(drink);
            _context.SaveChanges();

            return drink.Id;
        }


        public void DeleteDrink(int drinkId)
        {
            var drink = _context.Drinks.Find(drinkId);

            if(drink != null)
            {
                _context.Drinks.Remove(drink);
                _context.SaveChanges();
            }
        }

        public IQueryable<Drink> GetAllDrinks()
        {
            var drinks = _context.Drinks;

            return drinks;
        }

        public Drink GetDrink(int drinkId)
        {
            var drink = _context.Drinks.FirstOrDefault(d => d.Id == drinkId);

            return drink;
        }

        public void EditDrink(Drink editedDrink)
        {
            _context.Update(editedDrink);
            _context.SaveChanges();
        }

        public Drink GetDrinkById(int drinkId)
        {
            var drink = _context.Drinks.FirstOrDefault(d => d.Id == drinkId);

            return drink;
        }
    }
}

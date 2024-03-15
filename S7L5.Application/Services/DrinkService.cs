using AutoMapper;
using AutoMapper.QueryableExtensions;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Drink;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Application.Services
{
    public class DrinkService : IDrinkService
    {
        private readonly IMapper? _mapper;
        private readonly IDrinkRepository? _drinkRepository;

        public DrinkService(IMapper mapper, IDrinkRepository drinkRepository)
        {
            _mapper = mapper;
            _drinkRepository = drinkRepository;
        }

        public int AddDrink(NewDrinkVm newDrinkVm)
        {
            var drink = _mapper.Map<Drink>(newDrinkVm);
            var id = _drinkRepository.AddDrink(drink);

            return id;
        }

        public void DeleteDrink(int drinkId)
        {
            _drinkRepository.DeleteDrink(drinkId);
        }

        public IQueryable<Drink> GetAllDrinks()
        {
            var drinks = _drinkRepository.GetAllDrinks();

            return drinks;
        }

        public ListDrinkForListVm GetAllDrinksForList(int pageSize, int pageNumber, string filterString)
        {
            
            var drinks = _drinkRepository.GetAllDrinks().Where(c => c.Name.Contains(filterString.ToLower()))
                .ProjectTo<DrinkForListVm>(_mapper.ConfigurationProvider).ToList();

            var drinksToShow = drinks.Skip(pageSize * (pageNumber - 1)).Take(pageSize).ToList();

            var drinkList = new ListDrinkForListVm()
            {
                CurrentPage = pageNumber,
                PageSize = pageSize,
                FilterString = filterString,
                Drinks = drinksToShow,
                Count = drinks.Count
            };

            return drinkList;
        }

        public NewDrinkVm GetDrinkForEdit(int drinkId)
        {
            var drink = _drinkRepository.GetDrink(drinkId);
            var drinkVm = _mapper.Map<NewDrinkVm>(drink);

            return drinkVm;
        }

        public void EditDrink(NewDrinkVm editDrinkVm)
        {
            var editedDrink = _mapper.Map<Drink>(editDrinkVm);
            _drinkRepository.EditDrink(editedDrink);
        }

        public DrinkForListVm GetDrinkDetails(int drinkId)
        {
            var drink = _drinkRepository.GetDrinkById(drinkId);
            var drinkVm = _mapper.Map<DrinkForListVm>(drink);

            return drinkVm;
        }

    }
}

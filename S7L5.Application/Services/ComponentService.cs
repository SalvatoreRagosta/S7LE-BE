using AutoMapper;
using AutoMapper.QueryableExtensions;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Component;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PizzeriaImpulsMVC.Application.Services
{
    public class ComponentService : IComponentService
    {
        private readonly IComponentRepository _componentRepository;
        private readonly IPizzaRepository _pizzaRepository;
        private readonly IMapper? _mapper;

        public ComponentService(IComponentRepository componentRepository, IPizzaRepository pizzaRepository, IMapper mapper)
        {
            _componentRepository = componentRepository;
            _pizzaRepository = pizzaRepository;
            _mapper = mapper;
        }

        public int AddNewComponent(NewComponentVm newComponentVm)
        {
            var component = _mapper.Map<Component>(newComponentVm);
            var id = _componentRepository.AddComponent(component);

            return id;
        }

        public void DeleteComponent(int componentId)
        {
            var component = _componentRepository.GetComponent(componentId);
            var componentsPizzas = _pizzaRepository.GetComponentPizzasByComponentId(componentId);
            var pizzaIdsList = new List<int>();

            foreach (var componentPizza in componentsPizzas)
            {
                pizzaIdsList.Add(componentPizza.PizzaId);
            }

            _pizzaRepository.UpdatePizzaPrice(pizzaIdsList, component);
            _pizzaRepository.DeleteComponentPizzas(0, componentId);
            _componentRepository.DeleteComponent(componentId);
        }

        public ListComponentForListVm GetAllComponentsForList(int pageSize, int pageNumber, string filterString)
        {
            var components = _componentRepository.GetAllComponents().Where(c => c.Name.Contains(filterString.ToLower()))
                .ProjectTo<ComponentForListVm>(_mapper.ConfigurationProvider).ToList();

            var componentsToShow = components.Skip(pageSize * (pageNumber - 1)).Take(pageSize).ToList();

            var componentsList = new ListComponentForListVm()
            {
                CurrentPage = pageNumber,
                PageSize = pageSize,
                FilterString = filterString,
                Components = componentsToShow,
                Count = components.Count
            };

            return componentsList;
        }

        public List<ComponentForListVm> GetAllComponents()
        {
            var components = _componentRepository.GetAllComponents()
                .ProjectTo<ComponentForListVm>(_mapper.ConfigurationProvider).ToList();

            var componentList = new List<ComponentForListVm>();

            foreach (var component in components)
            {
                componentList.Add(component);
            }
            
            return componentList;
        }

        public NewComponentVm GetComponentForEdit(int componentId)
        {
            var component = _componentRepository.GetComponent(componentId);
            var componentVm = _mapper.Map<NewComponentVm>(component);

            return componentVm;
        }

        public void EditComponent(NewComponentVm editComponentVm)
        {
            var editedComponent = _mapper.Map<Component>(editComponentVm);
            _componentRepository.EditComponent(editedComponent);
        }

        public ComponentForListVm GetComponentDetails(int componentId)
        {
            var component = _componentRepository.GetComponentById(componentId);
            var componentVm = _mapper.Map<ComponentForListVm>(component);

            return componentVm;
        }
    }
}

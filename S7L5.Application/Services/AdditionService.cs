using AutoMapper;
using AutoMapper.QueryableExtensions;
using PizzeriaImpulsMVC.Application.Interfaces;
using PizzeriaImpulsMVC.Application.ViewModels.Addition;
using PizzeriaImpulsMVC.Domain.Interfaces;
using PizzeriaImpulsMVC.Domain.Models;

namespace PizzeriaImpulsMVC.Application.Services
{
    public class AdditionService : IAdditionService
    {
        private readonly IAdditionRepository? _additionRepository;
        private readonly IMapper? _mapper;

        public AdditionService(IAdditionRepository additionRepository, IMapper mapper)
        {
            _additionRepository = additionRepository;
            _mapper = mapper;
        }

        public int AddNewAddition(NewAdditionVm newAdditionVm)
        {
            var addition = _mapper.Map<Addition>(newAdditionVm);
            var id = _additionRepository.AddAddition(addition);

            return id;
        }

        public void DeleteAddition(int additionId)
        {
            _additionRepository.DeleteAddition(additionId);
        }

        public ListAdditionForListVm GetAllAdditionsForList(int pageSize, int pageNumber, string filterString)
        {
            var additions = _additionRepository.GetAllAdditions().Where(a => a.Name.Contains(filterString.ToLower()))
                .ProjectTo<AdditionForListVm>(_mapper.ConfigurationProvider).ToList();

            var additionsToShow = additions.Skip(pageSize * (pageNumber - 1)).Take(pageSize).ToList();

            var additionList = new ListAdditionForListVm()
            {
                CurrentPage = pageNumber,
                PageSize = pageSize,
                FilterString = filterString,
                Additions = additionsToShow,
                Count = additions.Count
            };

            return additionList;
        }

        public NewAdditionVm GetAdditionForEdit(int additionId)
        {
            var addition = _additionRepository.GetAddition(additionId);
            var additionVm = _mapper.Map<NewAdditionVm>(addition);

            return additionVm;
        }

        public void EditAddition(NewAdditionVm additionForEdit)
        {
            var editedAddition = _mapper.Map<Addition>(additionForEdit);
            _additionRepository.EditAddition(editedAddition);
        }

        public AdditionForListVm GetAdditionDetails(int additionId)
        {
            var addition = _additionRepository.GetAdditionById(additionId);
            var additionVm = _mapper.Map<AdditionForListVm>(addition);

            return additionVm;
        }
    }
}

#ifndef BITSTREAM_H
#define BITSTREAM_H

#include <vector>
#include <cstdint>
#include <type_traits>
#include <string>


class BitStream
{
private:
  std::vector<std::uint8_t> buffer;
  size_t m_WritePose = 0;
  size_t m_ReadPose = 0;

public:
  BitStream();
  BitStream(const std::uint8_t* data, size_t size);

  ///@name Побитовые операции
  ///@{
  /**
   * @brief Записывает один бит в поток
   * @param value Значение бита для записи
   */
  void WriteBit(bool value);
  /**
   * @brief Читает один бит из потока
   * @return Значение прочитанного бита
   */
  bool ReadBit();
  ///@}

  /**
   * @brief Записывает указанное количество бит в поток
   * @param value Значение для записи
   * @param bitCount Количество бит для записи
   */
  void WriteBits(uint32_t value, uint8_t bitCount);
  /**
   * @brief Читает указанное количество бит из потока
   * @param bitCount Количество бит для чтения
   * @return Значение прочитанных бит
   */
  uint32_t ReadBits(uint8_t bitCount);

  ///@name Операции с байтами
  ///@{
  /**
   * @brief Записывает массив байт в поток
   * @param data Указатель на данные для записи
   * @param size Размер данных в байтах
   */
  void WriteBytes(const void* data, size_t size);
  /**
   * @brief Читает массив байт из потока
   * @param data Указатель для записи прочитанных данных
   * @param size Размер данных в байтах для чтения
   */
  void ReadBytes(void* data, size_t size);
  ///@}

  ///@name Операции выравнивания
  ///@{
  /**
   * @brief Выравнивает указатель записи на границу байта
   */
  void AlignWrite();
  /**
   * @brief Выравнивает указатель чтения на границу байта
   */
  void AlignRead();
  ///@}

  /// @name Операции с template
  /// @{
  /**
   * @brief Записывает значение в поток
   * @tparam T Тип значения (должен быть тривиально копируемым)
   * @param value Значение для записи
   */
  template<typename T>
  void Write(const T& value)
  {
      static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
      WriteBytes(&value, sizeof(T));
  }

  /**
   * @brief Читает значение из потока
   * @tparam T Тип значения (должен быть тривиально копируемым)
   * @param value Ссылка для записи прочитанного значения
   */
  template<typename T>
  void Read(T& value)
  {
      static_assert(std::is_trivially_copyable_v<T>, "Type must be trivially copyable");
      ReadBytes(&value, sizeof(T));
  }
  ///@}

  /**
   * Специализация шаблона для записи строки
   * @brief Записывает строку в поток
   * @param value Строка для записи
   */
  void Write(const std::string& value);
  /**
   * Специализация шаблона для чтения строки
   * @brief Читает строку из потока
   * @param value Ссылка для записи прочитанной строки
   */
  void Read(std::string& value);

  ///@name Операции с массивами булевых значений
  ///@{
  /**
   * @brief Записывает массив булевых значений в поток
   * @param bools Вектор булевых значений для записи
   */
  void WriteBoolArray(const std::vector<bool>& bools);
  /**
   * @brief Читает массив булевых значений из потока
   * @return Вектор прочитанных булевых значений
   */
  std::vector<bool> ReadBoolArray();
  ///@}

  /// @name Полезные методы
  /// @{
  /**
   * @brief Возвращает указатель на данные в потоке
   * @return Указатель на данные в потоке
   */
  const std::uint8_t* GetData() const;
  /**
   * @brief Возвращает размер данных в потоке в байтах
   * @return Размер данных в потоке в байтах
   */
  size_t GetSizeBytes() const;
  /**
   * @brief Возвращает размер данных в потоке в битах
   * @return Размер данных в потоке в битах
   */
  size_t GetSizeBits() const;
  /**
   * @brief Сбрасывает указатель записи в начало потока
   */
  void ResetWrite();
  /**
   * @brief Сбрасывает указатель чтения в начало потока
   */
  void ResetRead();
  /**
   * @brief Очищает поток
   */
  void Clear();
  ///@}

  void WriteQuantizedFloat(float value, float min, float max, uint8_t bits);
  float ReadQuantizedFloat(float min, float max, uint8_t bits);
};

#endif // BITSTREAM_H
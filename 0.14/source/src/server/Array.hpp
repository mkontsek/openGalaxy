/* This file is part of openGalaxy.
 *
 * opengalaxy - a SIA receiver for Galaxy security control panels.
 * Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * as published by the Free Software Foundation, or (at your option)
 * any later version.
 *
 * In addition, as a special exception, the author of this program
 * gives permission to link the code of its release with the OpenSSL
 * project's "OpenSSL" library (or with modified versions of it that
 * use the same license as the "OpenSSL" library), and distribute the
 * linked executables. You must obey the GNU General Public License
 * in all respects for all of the code used other than "OpenSSL".
 * If you modify this file, you may extend this exception to your
 * version of the file, but you are not obligated to do so.
 * If you do not wish to do so, delete this exception statement
 * from your version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __OPENGALAXY_ARRAY_HPP__
#define __OPENGALAXY_ARRAY_HPP__

#include "atomic.h"

namespace openGalaxy {

template <typename T> class Array {

protected:
  volatile int m_nLength; // Array length
  T *m_ptData; // Array data

public:

  // Constructors
  Array();
  Array( int nLength );

  // Destructors
  ~Array();

  // Methods
  void erase();
  T& operator[]( int nIndex );
  volatile int size();
  void reallocate( int nNewLength );
  void resize( int nNewLength );
  void insert( T tValue, int nIndex );
  void prepend( T tValue );
  void append( T tValue );
  void remove( int nIndex );
};


template<typename T> class ObjectArray: public Array<T> {

public:
   // Constructors
  ObjectArray() : Array<T>() {}

  // Destructors
  ~ObjectArray();

  // Overloaded methods from Array<T>
  void erase();
  void reallocate( int nNewLength );
  void resize( int nNewLength );
  void remove( int nIndex );
};

// Implementation
//
// Because this is a template class the definition and
// implementation need to be in the same header file...

template <typename T> Array<T>::Array()
{
  m_nLength = 0;
  m_ptData = 0;
}

template <typename T> Array<T>::Array( int nLength )
{
  m_ptData = new T[nLength];
  m_nLength = nLength;
}

template <typename T> Array<T>::~Array()
{
  delete[] m_ptData;
}

template <typename T> void Array<T>::erase()
{
  delete[] m_ptData;
  m_ptData = 0;
  m_nLength = 0;
}

template <typename T> T& Array<T>::operator[]( int nIndex )
{
  if( !(nIndex >= 0 && nIndex < m_nLength ) ){
    throw new std::runtime_error("Array<T>::operator[]: nIndex out of bounds.");
  }
  return m_ptData[ nIndex ];
}

template <typename T> volatile int Array<T>::size()
{
  return m_nLength;
}

template <typename T> void Array<T>::reallocate( int nNewLength )
{
  erase();
  if( nNewLength <= 0 ) return;
  m_ptData = new T[ nNewLength ];
  m_nLength = nNewLength;
}

template <typename T> void Array<T>::resize( int nNewLength )
{
  if( nNewLength <= 0 ){
    erase();
  }
  else {
    T *ptData = new T[ nNewLength ];
    if(m_nLength > 0) {
      int nElementsToCopy = (nNewLength > m_nLength) ? m_nLength : nNewLength;
      for( int nIndex=0; nIndex < nElementsToCopy; nIndex++ ){
        ptData[nIndex] = m_ptData[nIndex];
      }
    }
    delete[] m_ptData;
    m_ptData = ptData;
    m_nLength = nNewLength;
  }
}

template <typename T> void Array<T>::insert( T tValue, int nIndex )
{
  if( !(nIndex >= 0 && nIndex <= m_nLength ) ){
    throw new std::runtime_error("Array<T>::insert(): nIndex out of bounds.");
  }

  T *ptData = new T[ m_nLength + 1 ];

  for( int nBefore=0; nBefore < nIndex; nBefore++ ){
    ptData[ nBefore ] = m_ptData[ nBefore ];
  }

  ptData[ nIndex ] = tValue;

  for( int nAfter=nIndex; nAfter < m_nLength; nAfter++ ){
    ptData[ nAfter + 1 ] = m_ptData[ nAfter ];
  }

  delete[] m_ptData;
  m_ptData = ptData;
  m_nLength += 1;
}

template <typename T> void Array<T>::prepend( T tValue )
{
  insert( tValue, 0 );
}

template <typename T> void Array<T>::append( T tValue)
{
  insert( tValue, m_nLength );
}

template <typename T> void Array<T>::remove( int nIndex )
{
  if( !(nIndex >= 0 && nIndex < m_nLength ) ){
    throw new std::runtime_error("Array<T>::remove(): nIndex out of bounds.");
  }

  T *ptData = new T[ m_nLength - 1 ];

  for( int nBefore = 0; nBefore < nIndex; nBefore++ ){
    ptData[ nBefore ] = m_ptData[ nBefore ];
  }

  for( int nAfter = nIndex + 1; nAfter < m_nLength; nAfter++ ){
    ptData[ nAfter - 1 ] = m_ptData[ nAfter ];
  }

  delete[] m_ptData;
  m_ptData = ptData;
  m_nLength -= 1;
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

template <typename T> ObjectArray<T>::~ObjectArray()
{
  ObjectArray<T>::erase();
}

template <typename T> void ObjectArray<T>::erase()
{
  for( int nIndex = 0; nIndex < Array<T>::m_nLength; nIndex++ ){
    delete Array<T>::m_ptData[nIndex];
  }
  Array<T>::erase();
}

template <typename T> void ObjectArray<T>::reallocate( int nNewLength )
{
   ObjectArray<T>::erase();
   Array<T>::reallocate( nNewLength );
}

template <typename T> void ObjectArray<T>::resize( int nNewLength )
{
  if( nNewLength <= 0 ){
    ObjectArray<T>::erase();
  }
  else {
    T *ptData = new T[ nNewLength ];
    if(Array<T>::m_nLength > 0) {
      for( int nIndex = 0; nIndex < Array<T>::m_nLength; nIndex++ ){
        if( nIndex < nNewLength ) ptData[ nIndex ] = Array<T>::m_ptData[ nIndex ];
        else delete Array<T>::m_ptData[ nIndex ];
      }
    }
    delete[] Array<T>::m_ptData;
    Array<T>::m_ptData = ptData;
    Array<T>::m_nLength = nNewLength;
  }
}

template <typename T> void ObjectArray<T>::remove( int nIndex )
{
  if( !(nIndex >=0 && nIndex < Array<T>::m_nLength ) ){
    throw new std::runtime_error("ObjectArray<T>::remove(): nIndex out of bounds.");
  }
  delete Array<T>::m_ptData[ nIndex ];
  Array<T>::remove( nIndex );
}

} // ends namespace openGalaxy

#endif


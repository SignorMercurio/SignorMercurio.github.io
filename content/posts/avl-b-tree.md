---
title: AVL 树和 B 树
date: 2018-06-13 20:39:29
tags:
  - C/C++
categories:
  - 编程语言
---

数据结构上机课花了点时间实现的两种相对复杂的数据结构。基本上在抄书。

<!--more-->

## AVL 树

包含了二叉树、二叉查找树和 AVL 树的实现，不过毕竟没有真正学过 C++，对 OOP 也还不算很熟悉，碰到了一些问题：

- 继承的类也不能访问父类的 private 成员，不过可以用 `using 父类:: 成员名 ` 的方式访问父类的 protected 成员
- 子类中重载了父类的某个成员函数后，对子类和父类中的该函数**同时**加 `virtual` 关键字修饰，可以在运行时判断具体需要调用的函数是哪一个版本

### 代码

```cpp
#include <iostream>
#include <stack>
using namespace std;

enum Balance_factor {left_higher, equal_height, right_higher};
enum Error_code {success, not_present, duplicate_error};

template <class Record>
struct Binary_node
{
    Record data;
    Binary_node<Record> *left, *right;

    Binary_node() {left = right = NULL;};
    Binary_node(const Record &x) {data = x; left = right = NULL;};

    virtual void set_balance(Balance_factor b) {};
    virtual Balance_factor get_balance() const {return equal_height;};
};

template <class Record>
class Binary_tree
{
public:
    Binary_tree() {root = NULL; count = 0;};
    bool empty() const {return !root;};
    int size() const {return count;};
    int height() const
    {
        if (!count) return 0;
        int tmp, i;
        for (tmp = 1, i = 0; tmp <= count; ++i) tmp <<= 1;
        return i;
    }
    void preorder(void (*visit)(Record &)) {recursive_preorder(root, visit);};
    void inorder(void (*visit)(Record &)) {recursive_inorder(root, visit);};
    void postorder(void (*visit)(Record &)) {recursive_postorder(root, visit);};
    void insert(Record &);
protected:
    Binary_node<Record> *root;
    int count;
    void recursive_preorder(Binary_node<Record> *sub_root, void (*visit)(Record &))
    {
        if (sub_root)
        {
            (*visit)(sub_root->data);
            recursive_preorder(sub_root->left, visit);
            recursive_preorder(sub_root->right, visit);
        }
    }
    void recursive_inorder(Binary_node<Record> *sub_root, void (*visit)(Record &))
    {
        if (sub_root)
        {
            recursive_inorder(sub_root->left, visit);
            (*visit)(sub_root->data);
            recursive_inorder(sub_root->right, visit);
        }
    }
    void recursive_postorder(Binary_node<Record> *sub_root, void (*visit)(Record &))
    {
        if (sub_root)
        {
            recursive_postorder(sub_root->left, visit);
            recursive_postorder(sub_root->right, visit);
            (*visit)(sub_root->data);
        }
    }
};

template <class Record>
void Binary_tree<Record>::insert(Record &x)
{
    if(empty())
    {
        root = new Binary_node<Record>(x);
        ++count;
        return;
    }
    stack<int> numbers;
    int item = 0, tmpcount = size();
    while (tmpcount> 0)
    {
        numbers.push((tmpcount&1) ? 1:2);
        tmpcount = (tmpcount-1)>>1;
    }
    Binary_node<Record> *current = root;
    while (numbers.size() > 1)
    {
        item = numbers.top();
        if (item == 1) current = current->left;
        if (item == 2) current = current->right;
           numbers.pop();
    }
    item = numbers.top();
    if (item == 1) current->left = new Binary_node<Record>(x);
    if (item == 2) current->right = new Binary_node<Record>(x);
    ++count;
}

template <class Record>
class Search_tree: public Binary_tree<Record>
{
public:
    Error_code insert(const Record &new_data)
    {
        Error_code result = search_and_insert(root, new_data);
        if (result == success) ++count;
        return result;
    }
    Error_code remove(const Record &target)
    {
        Error_code result = search_and_destroy(root, target);
        if (result == success) --count;
        return result;
    }
    Error_code tree_search(Record &target) const
    {
        Error_code result = success;
        Binary_node<Record> *found = search_for_node(root, target);
        if (!found) result = not_present;
        else target = found->data;
        return result;
    }
protected:
    using Binary_tree<Record>::root;
    using Binary_tree<Record>::count;

    Binary_node<Record> *search_for_node(Binary_node<Record>* sub_root, const Record &target) const;
    Error_code search_and_insert(Binary_node<Record> * &sub_root, const Record &new_data);
    Error_code search_and_destroy(Binary_node<Record>* &sub_root, const Record &target);
    Error_code remove_root(Binary_node<Record> * &sub_root);
};

template <class Record>
Binary_node<Record> *Search_tree<Record>::search_for_node(
Binary_node<Record>* sub_root, const Record &target) const
{
    if (!sub_root || sub_root->data == target)
        return sub_root;
    else if (sub_root->data <target)
        return search_for_node(sub_root->right, target);
    else return search_for_node(sub_root->left, target);
}

template <class Record>
Error_code Search_tree<Record>::search_and_insert(
Binary_node<Record> * &sub_root, const Record &new_data)
{
    if (!sub_root)
    {
        sub_root = new Binary_node<Record>(new_data);
        return success;
    }
    else if (new_data < sub_root->data)
        return search_and_insert(sub_root->left, new_data);
    else if (new_data> sub_root->data)
        return search_and_insert(sub_root->right, new_data);
    else return duplicate_error;
}

template <class Record>
Error_code Search_tree<Record>::remove_root(Binary_node<Record> * &sub_root)
{
    if (!sub_root) return not_present;
    Binary_node<Record> *to_delete = sub_root;
    if (!sub_root->right) sub_root = sub_root->left;
    else if (!sub_root->left) sub_root = sub_root->right;
    else {
        to_delete = sub_root->left;
        Binary_node<Record> *parent = sub_root;
        while (to_delete->right)
        {
            parent = to_delete;
            to_delete = to_delete->right;
        }
        sub_root->data = to_delete->data;
        if (parent == sub_root) sub_root->left = to_delete->left;
        else parent->right = to_delete->left;
    }
    delete to_delete;
    return success;
}

template <class Record>
Error_code Search_tree<Record>::search_and_destroy(
Binary_node<Record>* &sub_root, const Record &target)
{
    if (!sub_root || sub_root->data == target)
        return remove_root(sub_root);
    else if (target < sub_root->data)
        return search_and_destroy(sub_root->left, target);
    else
        return search_and_destroy(sub_root->right, target);
}

template <class Record>
struct AVL_node: public Binary_node<Record>
{
    using Binary_node<Record>::left;
    using Binary_node<Record>::right;
    using Binary_node<Record>::data;

    Balance_factor balance;

    AVL_node() {left = right = NULL; balance = equal_height;};
    AVL_node(const Record &x)
    {
        data = x;
        left = right = NULL;
        balance = equal_height;
    };

    void set_balance(Balance_factor b) {balance = b;};
    Balance_factor get_balance() const {return balance;};
};

template <class Record>
class AVL_tree: public Search_tree<Record>
{
public:
    Error_code insert(const Record &new_data)
    {
        bool taller;
        return avl_insert(root, new_data, taller);
    }
    Error_code remove(Record &new_data)
    {
        bool shorter = true;
        return avl_remove(root, new_data, shorter);
    };
private:
    using Binary_tree<Record>::root;

    Error_code avl_insert(Binary_node<Record> * &sub_root, const Record &new_data, bool &taller);
    void rotate_left(Binary_node<Record> * &sub_root);
    void rotate_right(Binary_node<Record> * &sub_root);
    void right_balance(Binary_node<Record> * &sub_root);
    void left_balance(Binary_node<Record> * &sub_root);

    Error_code avl_remove(Binary_node<Record> * &sub_root, Record &new_data, bool &shorter);
    bool right_balance2(Binary_node<Record> * &sub_root);
    bool left_balance2(Binary_node<Record> * &sub_root);
};

template <class Record>
Error_code AVL_tree<Record>::avl_insert(Binary_node<Record> * &sub_root,
const Record &new_data, bool &taller)
{
    Error_code result = success;
    if (!sub_root)
    {
        sub_root = new AVL_node<Record>(new_data);
        taller = true;
    }
    else if (new_data == sub_root->data)
    {
        result = duplicate_error;
        taller = false;
    }
    else if (new_data < sub_root->data)
    {
        result = avl_insert(sub_root->left, new_data, taller);
        if (taller)
        switch (sub_root->get_balance())
        {
        case left_higher:
            left_balance(sub_root);
            taller = false;
            break;
        case equal_height:
            sub_root->set_balance(left_higher);
            break;
        case right_higher:
            sub_root->set_balance(equal_height);
            taller = false;
            break;
        }
    }
    else
    {
        result = avl_insert(sub_root->right, new_data, taller);
        if (taller)
        switch (sub_root->get_balance())
        {
        case left_higher:
            sub_root->set_balance(equal_height);
            taller = false;
            break;
        case equal_height:
            sub_root->set_balance(right_higher);
            break;
        case right_higher:
            right_balance(sub_root);
            taller = false;
            break;
        }
    }
    return result;
}

template <class Record>
void AVL_tree<Record>::rotate_left(Binary_node<Record> * &sub_root)
{
    if (!sub_root || !sub_root->right)
        cout <<"WARNING: program error detected in rotate left" << endl;
    else
    {
        Binary_node<Record> *right_tree = sub_root->right;
        sub_root->right = right_tree->left;
        right_tree->left = sub_root;
        sub_root = right_tree;
    }
}

template <class Record>
void AVL_tree<Record> :: rotate_right(Binary_node<Record> * &sub_root)
{
    if (!sub_root || !sub_root->left)
        cout <<"WARNING: program error detected in rotate right" << endl;
    else
    {
        Binary_node<Record> *left_tree = sub_root->left;
        sub_root->left = left_tree->right;
        left_tree->right = sub_root;
        sub_root = left_tree;
    }
}

template <class Record>
void AVL_tree<Record>::right_balance(Binary_node<Record> * &sub_root)
{
    Binary_node<Record> * &right_tree = sub_root->right;
    switch (right_tree->get_balance())
    {
    case right_higher:
        sub_root->set_balance(equal_height);
        right_tree->set_balance(equal_height);
        rotate_left(sub_root);
        break;
    case equal_height:
        cout <<"WARNING: program error in right balance" << endl;
    case left_higher:
        Binary_node<Record> *sub_tree = right_tree->left;
        switch (sub_tree->get_balance())
        {
        case equal_height:
            sub_root->set_balance(equal_height);
            right_tree->set_balance(equal_height);
            break;
        case left_higher:
            sub_root->set_balance(equal_height);
            right_tree->set_balance(right_higher);
            break;
        case right_higher:
            sub_root->set_balance(left_higher);
            right_tree->set_balance(equal_height);
            break;
        }
        sub_tree->set_balance(equal_height);
        rotate_right(right_tree);
        rotate_left(sub_root);
        break;
    }
}

template <class Record>
void AVL_tree<Record>::left_balance(Binary_node<Record> * &sub_root)
{
    Binary_node<Record> * &left_tree = sub_root->left;
    switch (left_tree->get_balance())
    {
    case left_higher:
        sub_root->set_balance(equal_height);
        left_tree->set_balance(equal_height);
        rotate_right(sub_root);
        break;
    case equal_height:
        cout <<"WARNING: program error in right balance" << endl;
    case right_higher:
        Binary_node<Record> *sub_tree = left_tree->right;
        switch (sub_tree->get_balance())
        {
        case equal_height:
            sub_root->set_balance(equal_height);
            left_tree->set_balance(equal_height);
            break;
        case right_higher:
            sub_root->set_balance(equal_height);
            left_tree->set_balance(left_higher);
            break;
        case left_higher:
            sub_root->set_balance(right_higher);
            left_tree->set_balance(equal_height);
            break;
        }
        sub_tree->set_balance(equal_height);
        rotate_left(left_tree);
        rotate_right(sub_root);
        break;
    }
}

template <class Record>
Error_code AVL_tree<Record>::avl_remove(Binary_node<Record> * &sub_root,
Record &new_data, bool &shorter)
{
    Error_code result = success;
    Record sub_record;
    if (!sub_root)
    {
        shorter = false;
        return not_present;
    }
    else if (new_data == sub_root->data)
    {
        Binary_node<Record> *to_delete = sub_root;
        if (!sub_root->right)
        {
            sub_root = sub_root->left;
            shorter = true;
            delete to_delete;
            return success;
        }
        else if (!sub_root->left)
        {
            sub_root = sub_root->right;
            shorter = true;
            delete to_delete;
            return success;
        }
        else
        {
            to_delete = sub_root->left;
            Binary_node<Record> *parent = sub_root;
            while (to_delete->right)
            {
                parent = to_delete;
                to_delete = to_delete->right;
            }
            new_data = to_delete->data;
            sub_record = new_data;
        }
    }
    if (new_data < sub_root->data)
    {
        result = avl_remove(sub_root->left, new_data, shorter);
        if (sub_record.the_key()) sub_root->data = sub_record;
        if (shorter)
        switch (sub_root->get_balance())
        {
        case left_higher:
            sub_root->set_balance(equal_height);
            break;
        case equal_height:
            sub_root->set_balance(right_higher);
            shorter = false;
            break;
        case right_higher:
            shorter = right_balance2(sub_root);
            break;
        }
    }
    if (new_data> sub_root->data)
    {
        result = avl_remove(sub_root->right, new_data, shorter);
        if (sub_record.the_key()) sub_root->data = sub_record;
        if (shorter)
        switch (sub_root->get_balance())
        {
        case left_higher:
            shorter = left_balance2(sub_root);
            break;
        case equal_height:
            sub_root->set_balance(left_higher);
            shorter = false;
            break;
        case right_higher:
            sub_root->set_balance(equal_height);
            break;
        }
    }
    return result;
}

template <class Record>
bool AVL_tree<Record>::right_balance2(Binary_node<Record> * &sub_root)
{
    bool shorter;
    Binary_node<Record> * &right_tree = sub_root->right;
    switch (right_tree->get_balance())
    {
    case right_higher:
        sub_root->set_balance(equal_height);
        right_tree->set_balance(equal_height);
        rotate_left(sub_root);
        shorter = true;
        break;
    case equal_height:
        right_tree->set_balance(left_higher);
        rotate_left(sub_root);
        shorter = false;
        break;
    case left_higher:
        Binary_node<Record> *sub_tree = right_tree->left;
        switch (sub_tree->get_balance())
        {
        case equal_height:
            sub_root->set_balance(equal_height);
            right_tree->set_balance(equal_height);
            break;
        case left_higher:
            sub_root->set_balance(equal_height);
            right_tree->set_balance(right_higher);
            break;
        case right_higher:
            sub_root->set_balance(left_higher);
            right_tree->set_balance(equal_height);
            break;
        }
        sub_tree->set_balance(equal_height);
        rotate_right(right_tree);
        rotate_left(sub_root);
        shorter = true;
        break;
    }
    return shorter;
}

template <class Record>
bool AVL_tree<Record>::left_balance2(Binary_node<Record> * &sub_root)
{
    bool shorter;
    Binary_node<Record> * &left_tree = sub_root->left;
    switch (left_tree->get_balance())
    {
    case left_higher:
        sub_root->set_balance(equal_height);
        left_tree->set_balance(equal_height);
        rotate_right(sub_root);
        shorter = true;
        break;
    case equal_height:
        left_tree->set_balance(right_higher);
        rotate_right(sub_root);
        shorter = false;
        break;
    case right_higher:
        Binary_node<Record> *sub_tree = left_tree->right;
        switch (sub_tree->get_balance())
        {
        case equal_height:
            sub_root->set_balance(equal_height);
            left_tree->set_balance(equal_height);
            break;
        case right_higher:
            sub_root->set_balance(equal_height);
            left_tree->set_balance(left_higher);
            break;
        case left_higher:
            sub_root->set_balance(right_higher);
            left_tree->set_balance(equal_height);
            break;
        }
        sub_tree->set_balance(equal_height);
        rotate_left(left_tree);
        rotate_right(sub_root);
        shorter = true;
        break;
    }
    return shorter;
}

template <class Record>
void print(Record &x)
{
    cout << x <<" ";
}

typedef char Record;

int main()
{
    AVL_tree<Record> mytree;
    mytree.insert('A');
    mytree.insert('V');
    mytree.insert('L');
    mytree.insert('T');
    mytree.insert('R');
    mytree.insert('E');
    mytree.insert('I');
    mytree.insert('S');
    mytree.insert('O');
    mytree.insert('K');

    cout <<"Preorder:" << endl;
    mytree.preorder(print);
    cout << endl << endl;
    cout <<"Inorder:" << endl;
    mytree.inorder(print);
    cout << endl << endl;
    cout <<"Postorder:" << endl;
    mytree.postorder(print);
    cout << endl << endl;

    cin.get();
    return 0;
}
```

## B 树

这里不赘述具体原理了，只记录一下代码。

说起来，B 树又叫 B-树，然而中间并不是减号而是连接符；同时，数据库索引使用的 B+ 树中间的 + 号又真的是加号……

### 代码

```cpp
#include <iostream>
using namespace std;

template <class Record, int order>
struct B_node
{
    int cnt;
    Record data[order-1];
    B_node<Record, order> *branch[order];
    B_node() {cnt = 0;}
};

enum Error_code {not_present, duplicate_error, overflow, success};

template<class Record,int order>
class B_tree
{
public:
    B_tree() {root = nullptr;}
    Error_code search_tree(Record &target)
    {
        return recursive_search_tree(root, target);
    }
    Error_code insert(const Record &new_entry);
    Error_code remove(const Record &target);
private:
    B_node<Record, order> *root;
    Error_code recursive_search_tree(B_node<Record, order> *current, Record &target);
    Error_code search_node(B_node<Record, order> *current, const Record &target, int &pos);

    Error_code push_down(B_node<Record, order> *current, const Record &new_entry, Record &median, B_node<Record, order> * &right_branch);
    void push_in(B_node<Record, order> *current, const Record &entry, B_node<Record, order> *right_branch, int pos);
    void split_node(B_node<Record, order> *current, const Record &extra_entry, B_node<Record, order> *extra_branch, int pos, B_node<Record, order> * &right_half, Record &median);

    Error_code recursive_remove(B_node<Record, order> *current, const Record &target);
    void remove_data(B_node<Record, order> *current, int pos)
    {
        for (int i = pos; i < current->cnt-1; ++i)
            current->data[i] = current->data[i+1];
        --current->cnt;
    }
    void copy_in_predecessor(B_node<Record, order> *current, int pos)
    {
        B_node<Record, order> *leaf = current->branch[pos];
        while (leaf->branch[leaf->cnt]) leaf = leaf->branch[leaf->cnt];
        current->data[pos] = leaf->data[leaf->cnt-1];
    }
    void restore(B_node<Record, order> *current, int pos);
    void move_left(B_node<Record, order> *current, int pos);
    void move_right(B_node<Record, order> *current, int pos);
    void combine(B_node<Record, order> *current, int pos);
};

template<class Record, int order>
Error_code B_tree<Record, order>::recursive_search_tree(B_node<Record, order> *current, Record &target)
{
    Error_code result = not_present;
    int pos;
    if (current)
    {
        result = search_node(current, target, pos);
        if (result == not_present)
            result = recursive_search_tree(current->branch[pos], target);
        else
            target = current->data[pos];
    }
    return result;
}

template<class Record, int order>
Error_code B_tree<Record, order>::search_node(B_node<Record, order> *current, const Record &target, int &pos)
{
    pos = 0;
    while (pos < current->cnt && target > current->data[pos]) ++pos;
    if (pos < current->cnt && target == current->data[pos]) return success;
    else return not_present;
}

template<class Record, int order>
Error_code B_tree<Record, order>::insert(const Record &new_entry)
{
    Record median;
    B_node<Record, order> *right_branch, *new_root;
    Error_code result = push_down(root, new_entry, median, right_branch);
    if (result == overflow)
    {
        new_root = new B_node<Record, order>;
        new_root->cnt = 1;
        new_root->data[0] = median;
        new_root->branch[0] = root;
        new_root->branch[1] = right_branch;
        root = new_root;
        result = success;
    }
    return result;
}

template<class Record, int order>
Error_code B_tree<Record, order>::push_down(B_node<Record, order> *current, const Record &new_entry, Record &median, B_node<Record, order> * &right_branch)
{
    Error_code result;
    int pos;
    if (!current)
    {
        median = new_entry;
        right_branch = nullptr;
        result = overflow;
    }
    else
    {
        if (search_node(current, new_entry, pos) == success)
            result = duplicate_error;
        else
        {
            Record extra_entry;
            B_node<Record, order> *extra_branch;
            result = push_down(current->branch[pos], new_entry, extra_entry, extra_branch);
            if (result == overflow)
            {
                if (current->cnt <order-1)
                {
                    result = success;
                    push_in(current, extra_entry, extra_branch, pos);
                }else
                    split_node(current, extra_entry, extra_branch, pos, right_branch, median);
            }
        }
    }
    return result;
}

template<class Record, int order>
void B_tree<Record, order>::push_in(B_node<Record, order> *current, const Record &entry, B_node<Record, order> *right_branch, int pos)
{
    for (int i = current->cnt; i > pos; --i)
    {
        current->data[i] = current->data[i-1];
        current->branch[i+1] = current->branch[i];
    }
    current->data[pos] = entry;
    current->branch[pos+1] = right_branch;
    ++current->cnt;
}

template<class Record, int order>
void  B_tree<Record, order>::split_node(B_node<Record, order> *current, const Record &extra_entry, B_node<Record, order> *extra_branch, int pos, B_node<Record, order> * &right_half, Record &median)
{
    right_half = new B_node<Record, order>;
    int mid = order>>1;
    if (pos <= mid)
    {
        for (int i = mid; i < order-1; ++i)
        {
            right_half->data[i-mid] = current->data[i];
            right_half->branch[i+1-mid] = current->branch[i+1];
        }
        current->cnt = mid;
        right_half->cnt = order - mid - 1;
        push_in(current, extra_entry, extra_branch, pos);
    }
    else
    {
        ++mid;
        for (int i = mid; i < order-1; ++i)
        {
            right_half->data[i-mid] = current->data[i];
            right_half->branch[i+1-mid] = current->branch[i+1];
        }
        current->cnt = mid;
        right_half->cnt = order - 1 - mid;
        push_in(right_half, extra_entry, extra_branch, pos-mid);
    }
    median = current->data[current->cnt-1];
    right_half->branch[0] = current->branch[current->cnt];
    --current->cnt;
}

template <class Record, int order>
Error_code B_tree<Record, order>::remove(const Record &target)
{
    Error_code result;
    result = recursive_remove(root, target);
    if (root && !root->cnt)
    {
        B_node<Record, order> *old_root = root;
        root = root->branch[0];
        delete old_root;
    }
    return result;
}

template <class Record, int order>
Error_code B_tree<Record, order>::recursive_remove(B_node<Record, order> *current, const Record &target)
{
    Error_code result;
    int pos;
    if (!current) result = not_present;
    else
    {
        if (search_node(current, target, pos) == success)
        {
            result = success;
            if (current->branch[pos])
            {
                copy_in_predecessor(current, pos);
                recursive_remove(current->branch[pos], current->data[pos]);
            }
            else remove_data(current, pos);
        }else
            result = recursive_remove(current->branch[pos], target);

        if (current->branch[pos])
            if (current->branch[pos]->cnt <((order-1)>>1))
                restore(current, pos);
    }
    return result;
}

template <class Record, int order>
void B_tree<Record, order>::restore(B_node<Record, order> *current, int pos)
{
    if (pos == current->cnt)
        if (current->branch[pos-1]->cnt > ((order-1)>>1))
            move_right(current, pos-1);
        else
            combine(current, pos);
    else if (!pos)
        if (current->branch[1]->cnt > ((order-1)>>1))
            move_left(current, 1);
        else
            combine(current, 1);
    else
        if (current->branch[pos-1]->cnt > ((order-1)>>1))
            move_right(current, pos-1);
        else if (current->branch[pos+1]->cnt > ((order-1)>>1))
            move_left(current, pos+1);
        else combine(current, pos);
}

template <class Record, int order>
void B_tree<Record, order>::move_left(B_node<Record, order> *current, int pos)
{
    B_node<Record, order>
        *left_branch = current->branch[pos-1],
        *right_branch = current->branch[pos];
    left_branch->data[left_branch->cnt] = current->data[pos-1];
    left_branch->branch[++left_branch->cnt] = right_branch->branch[0];
    current->data[pos-1] = right_branch->data[0];
    --right_branch->cnt;
    for (int i = 0; i < right_branch->cnt; ++i)
    {
        right_branch->data[i] = right_branch->data[i+1];
        right_branch->branch[i] = right_branch->branch[i+1];
    }
    right_branch->branch[right_branch->cnt] =
    right_branch->branch[right_branch->cnt+1];
}

template <class Record, int order>
void B_tree<Record, order>::move_right(B_node<Record, order> *current, int pos)
{
    B_node<Record, order>
        *right_branch = current->branch[pos+1],
        *left_branch = current->branch[pos];
    right_branch->branch[right_branch->cnt+1] =
    right_branch->branch[right_branch->cnt];
    for (int i = right_branch->cnt; i > 0; --i)
    {
        right_branch->data[i] = right_branch->data[i-1];
        right_branch->branch[i] = right_branch->branch[i-1];
    }
    ++right_branch->cnt;
    right_branch->data[0] = current->data[pos];
    right_branch->branch[0] = left_branch->branch[left_branch->cnt--];
    current->data[pos] = left_branch->data[left_branch->cnt];
}

template <class Record, int order>
void B_tree<Record, order>::combine(B_node<Record, order> *current, int pos)
{
    int i;
    B_node<Record, order>
        *left_branch = current->branch[pos-1],
        *right_branch = current->branch[pos];
    left_branch->data[left_branch->cnt] = current->data[pos-1];
    left_branch->branch[++left_branch->cnt] = right_branch->branch[0];
    for (i = 0; i < right_branch->cnt; ++i)
    {
        left_branch->data[left_branch->cnt] = right_branch->data[i];
        left_branch->branch[++left_branch->cnt] = right_branch->branch[i+1];
    }
    --current->cnt;
    for (i = pos-1; i < current->cnt; ++i)
    {
        current->data[i] = current->data[i+1];
        current->branch[i+1] = current->branch[i+2];
    }
    delete right_branch;
}

int main()
{
    B_tree<char, 5> mybtree;
    mybtree.insert('a');
    mybtree.insert('g');
    mybtree.insert('f');
    mybtree.insert('b');
    mybtree.insert('k');
    mybtree.insert('d');
    mybtree.insert('h');
    mybtree.insert('m');
    mybtree.insert('j');
    mybtree.insert('e');
    mybtree.insert('s');
    mybtree.insert('i');
    mybtree.insert('r');
    mybtree.insert('x');
    mybtree.insert('c');
    mybtree.insert('l');
    mybtree.insert('n');
    mybtree.insert('t');
    mybtree.insert('u');
    mybtree.insert('p');
    char target = 'k';
    cout <<mybtree.search_tree(target);
    mybtree.remove('k');
    cout <<mybtree.search_tree(target);
    cin.get();
    return 0;
}
```

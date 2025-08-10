import { DataTypes } from 'sequelize';
import { sequelize } from './index.js';

export const Post = sequelize.define('Post', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
    title: { type: DataTypes.STRING },
    content: { type: DataTypes.STRING },
    userId: { type: DataTypes.STRING },
}, { tableName: 'posts' });
